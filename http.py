import subprocess
import sys
import os
import platform
import shutil
import textwrap
import time

# --- Go语言源代码 (内嵌) ---
# 这部分是高性能的Go扫描器核心代码，负责执行实际的扫描任务。
# 它采用了高精度验证逻辑，确保扫描结果的准确性。
GO_SOURCE_CODE = r"""
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Task 定义了单个扫描任务，包含代理地址和可能的认证信息
type Task struct {
	ProxyAddress string
	Username     string
	Password     string
}

// HttpbinResponse 用于解析验证网站 httpbin.org 返回的JSON数据
type HttpbinResponse struct {
	Origin string `json:"origin"`
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime)

	// --- 命令行参数定义 ---
	proxyFile := flag.String("pfile", "", "代理列表文件路径 (格式: ip:port)")
	credFile := flag.String("cfile", "", "(可选) 认证信息文件路径 (格式: username:password)")
	targetURL := flag.String("target", "http://httpbin.org/ip", "用于验证代理IP回显的URL")
	timeout := flag.Int("timeout", 10, "每个代理的连接超时时间 (秒)")
	workers := flag.Int("workers", 100, "并发扫描的协程数量")
	outputFile := flag.String("output", "valid_proxies.txt", "保存有效代理的结果文件")
	flag.Parse()

	if *proxyFile == "" {
		fmt.Println("错误: 必须提供代理列表文件路径。")
		os.Exit(1)
	}

	proxies, err := readLines(*proxyFile)
	if err != nil {
		log.Fatalf("无法读取代理文件 %s: %v", *proxyFile, err)
	}

	var credentials []string
	if *credFile != "" {
		credentials, err = readLines(*credFile)
		if err != nil {
			log.Fatalf("无法读取认证文件 %s: %v", *credFile, err)
		}
	}

	// --- 任务分配 ---
	var tasks []Task
	if len(credentials) > 0 {
		// 如果提供了认证文件，则为每个代理尝试每一种认证组合
		for _, p := range proxies {
			for _, c := range credentials {
				parts := strings.SplitN(c, ":", 2)
				if len(parts) == 2 {
					tasks = append(tasks, Task{ProxyAddress: p, Username: parts[0], Password: parts[1]})
				}
			}
		}
	} else {
		// 如果没有认证文件，则直接创建无认证的任务
		for _, p := range proxies {
			tasks = append(tasks, Task{ProxyAddress: p})
		}
	}
	log.Printf("正在处理 %s。本批次总扫描任务数: %d。", *proxyFile, len(tasks))

	// --- 并发控制 ---
	taskChan := make(chan Task, *workers)
	resultChan := make(chan string, len(tasks))
	var wg sync.WaitGroup

	// 启动指定数量的 worker 协程
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(&wg, taskChan, resultChan, *targetURL, time.Duration(*timeout)*time.Second)
	}

	// 将所有任务放入任务管道
	go func() {
		for _, task := range tasks {
			taskChan <- task
		}
		close(taskChan)
	}()

	// 等待所有 worker 完成后关闭结果管道
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// --- 结果处理 ---
	log.Println("已启动高精度扫描...")
	var validProxies []string
	outFile, err := os.Create(*outputFile)
	if err != nil {
		log.Fatalf("无法创建输出文件 %s: %v", *outputFile, err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	for result := range resultChan {
		log.Printf("✅ 发现高精度有效代理: %s", result)
		validProxies = append(validProxies, result)
		fmt.Fprintln(writer, result)
		writer.Flush() // 实时写入文件
	}

	log.Printf("批次 %s 扫描完成！在本批次中发现 %d 个有效代理。", *proxyFile, len(validProxies))
}

// worker 是执行扫描任务的协程
func worker(wg *sync.WaitGroup, tasks <-chan Task, results chan<- string, targetURL string, timeout time.Duration) {
	defer wg.Done()
	for task := range tasks {
		fullProxyURL := formatProxyURL(task)
		if checkProxy(task.ProxyAddress, fullProxyURL, targetURL, timeout) {
			results <- fullProxyURL
		}
	}
}

// checkProxy 是核心的代理验证函数，采用IP回显方式
func checkProxy(proxyAddr, proxyURLStr, targetURL string, timeout time.Duration) bool {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return false
	}
	
	proxyHost, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return false // 地址格式必须是 ip:port
	}

	// 配置HTTP客户端，指定代理和超时
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   timeout,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout + (5 * time.Second), // 总超时比连接超时稍长
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false // 状态码不是200 OK，无效
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	// 解析返回的JSON
	var result HttpbinResponse
	if err := json.Unmarshal(body, &result); err != nil {
		// 如果返回的不是JSON（例如是一个HTML页面），则判定为无效代理
		return false
	}

	// 关键验证：检查返回的IP地址是否与代理服务器的IP地址一致
	if strings.Contains(result.Origin, proxyHost) {
		return true
	}

	return false
}

// readLines 从文件中逐行读取内容
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { // 忽略空行和注释行
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// formatProxyURL 根据任务信息格式化代理URL
func formatProxyURL(task Task) string {
	if task.Username != "" && task.Password != "" {
		return fmt.Sprintf("http://%s:%s@%s", url.QueryEscape(task.Username), url.QueryEscape(task.Password), task.ProxyAddress)
	}
	return fmt.Sprintf("http://%s", task.ProxyAddress)
}
"""

# --- Python 包装器和交互逻辑 ---
# 这部分代码负责提供用户友好的交互界面，并管理Go程序的编译、运行和清理。

def styled(message, style=""):
    """返回带颜色和样式的字符串，用于美化终端输出。"""
    styles = {
        "header": "\033[95m\033[1m",
        "blue": "\033[94m",
        "green": "\033[92m",
        "warning": "\033[93m\033[1m",
        "danger": "\033[91m\033[1m",
        "bold": "\033[1m",
        "underline": "\033[4m",
        "end": "\033[0m",
    }
    return f"{styles.get(style, '')}{message}{styles.get('end', '')}"

def get_user_input(prompt, default_value=None):
    """获取用户输入，支持默认值和空值检查。"""
    prompt_text = f"{prompt} (默认: {default_value}): " if default_value else f"{prompt}: "
    while True:
        value = input(prompt_text) or default_value
        if value and value.strip():
            return value
        if default_value is None:
            print(styled("输入不能为空，请重新输入。", "warning"))

def create_example_file_if_not_exists(filename, content):
    """如果文件不存在，则创建一个带有示例内容的模板文件。"""
    if not os.path.exists(filename):
        print(styled(f"\n提示: 文件 '{filename}' 不存在，为您创建一个示例。", "blue"))
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(textwrap.dedent(content).strip() + "\n")
            print(f"示例文件 '{filename}' 创建成功。请根据需要修改其内容。")
        except IOError as e:
            print(styled(f"错误: 无法创建文件 '{filename}': {e}", "danger"))
            return False
    return True

def find_go_executable():
    """
    智能寻找Go可执行文件路径，解决环境变量问题。
    这是确保脚本在 `screen` 等干净环境下也能运行的关键。
    """
    # 1. 检查系统PATH环境变量
    if shutil.which("go"):
        return shutil.which("go")
    
    # 2. 检查常见安装路径
    common_paths = [
        "/usr/local/go/bin/go",
        "/usr/bin/go",
        "/snap/bin/go",
        os.path.expanduser("~/go/bin/go")
    ]
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            print(styled(f"在标准路径中找到Go: {path}", "green"))
            return path
            
    # 3. 如果都找不到，则主动询问用户
    print(styled("\n错误: 自动查找 'go' 命令失败。", "danger"))
    print("这可能是因为Go没有安装，或者安装在了非标准位置，或者环境变量未生效。")
    while True:
        manual_path = input("> " + styled("请手动输入 'go' 命令的完整路径 (例如: /opt/go1.22/bin/go): ", "bold"))
        if manual_path and os.path.exists(manual_path) and os.access(manual_path, os.X_OK):
            return manual_path
        else:
            print(styled(f"路径 '{manual_path}' 无效或不可执行，请重新输入。", "warning"))

def split_file(large_file_path, lines_per_chunk):
    """将大文件分割成多个小文件块，以避免内存不足。"""
    chunk_files = []
    try:
        with open(large_file_path, 'r', encoding='utf-8', errors='ignore') as f_in:
            file_count = 0
            line_count = 0
            f_out = None
            for line in f_in:
                if line_count % lines_per_chunk == 0:
                    if f_out: f_out.close()
                    file_count += 1
                    chunk_filename = f"{large_file_path}.part_{file_count}.tmp"
                    chunk_files.append(chunk_filename)
                    f_out = open(chunk_filename, 'w', encoding='utf-8')
                f_out.write(line)
                line_count += 1
            if f_out: f_out.close()
        if not chunk_files and os.path.exists(large_file_path):
             chunk_filename = f"{large_file_path}.part_1.tmp"
             open(chunk_filename, 'w').close()
             chunk_files.append(chunk_filename)
        return chunk_files
    except Exception as e:
        print(styled(f"错误: 分割文件 '{large_file_path}' 时失败: {e}", "danger"))
        return None

def main():
    """主函数，运行整个交互式向导。"""
    print(styled("="*60, "header"))
    print(styled("   欢迎使用高精度HTTP代理扫描向导 (最终版)", "header"))
    print(styled("="*60, "header"))
    
    go_cmd = find_go_executable()
    if not go_cmd:
        sys.exit(1)
    print(styled(f"将使用此Go命令进行编译: {go_cmd}", "green"))

    print(styled("\n重要警告:", "danger"))
    print("1. 本工具仅用于学习和研究网络编程，严禁用于任何非法用途。")
    print("2. " + styled("未经授权对他方网络进行扫描是违法行为。", "underline") + " 请在您自己的或授权的网络环境中进行测试。")
    print("3. 任何因滥用本工具导致的法律后果，由使用者自行承担。")
    
    try:
        if input("\n> " + styled("您是否理解并同意以上条款？(输入 'yes' 继续): ", "bold")).lower() != 'yes':
            print(styled("\n操作已取消。", "warning"))
            sys.exit(0)
    except KeyboardInterrupt:
        print(styled("\n操作已取消。", "warning"))
        sys.exit(0)

    # --- 交互式配置 ---
    print(styled("\n--- 第一步: 代理文件 ---", "blue"))
    proxy_file = get_user_input("> 请输入代理文件路径", "proxies.txt")
    create_example_file_if_not_exists(proxy_file, "# 请在此处填入代理地址, 格式为 ip:port, 每行一个。")

    print(styled("\n--- 第二步: 文件处理 ---", "blue"))
    files_to_scan = [proxy_file]
    split_was_done = False
    if input("> 是否需要将大文件分割成小块以节省内存? (yes/no) ").lower() == 'yes':
        lines_per_file = int(get_user_input("> 每个小文件包含多少行代理?", "5000"))
        print(styled(f"正在将 '{proxy_file}' 分割成每份 {lines_per_file} 行的小文件...", "blue"))
        chunk_files = split_file(proxy_file, lines_per_file)
        if chunk_files:
            files_to_scan = chunk_files
            split_was_done = True
            print(styled(f"分割完成！共生成 {len(files_to_scan)} 个小文件。", "green"))
        else:
            print(styled("分割失败，将继续扫描原始文件。", "warning"))
    
    print(styled("\n--- 第三步: 密码本 ---", "blue"))
    cred_file = None
    if get_user_input("> 是否使用密码本扫描需要认证的代理? (yes/no)", "no").lower() == 'yes':
        cred_file = get_user_input("> 请输入密码本文件路径", "credentials.txt")
        create_example_file_if_not_exists(cred_file, "# 请在此处填入账号密码, 格式为 username:password, 每行一个。")

    print(styled("\n--- 第四步: 扫描参数 ---", "blue"))
    workers = get_user_input("> 请输入并发任务数", "100")
    timeout = get_user_input("> 请输入超时时间 (秒)", "10")
    output_file = get_user_input("> 请输入最终结果保存路径", "valid_proxies.txt")

    # --- 执行 ---
    go_source_file = "scanner_temp.go"
    exec_name = "scanner_exec.exe" if platform.system() == "Windows" else "scanner_exec"
    
    try:
        print(styled("\n正在预编译高精度Go扫描器...", "blue"))
        with open(go_source_file, "w", encoding="utf-8") as f:
            f.write(GO_SOURCE_CODE)
        os.environ["GOCACHE"] = "/tmp/gocache"
        os.makedirs("/tmp/gocache", exist_ok=True)
        compile_process = subprocess.run([go_cmd, "build", "-o", exec_name, go_source_file], capture_output=True, text=True, encoding='utf-8')
        if compile_process.returncode != 0:
            raise subprocess.CalledProcessError(compile_process.returncode, compile_process.args, output=compile_process.stdout, stderr=compile_process.stderr)
        print(styled("预编译成功!", "green"))

        # 确保最终结果文件是空的
        open(output_file, 'w').close()
        total_valid_proxies = 0

        # 循环扫描所有文件块
        for i, current_file in enumerate(files_to_scan):
            print(styled(f"\n--- 🚀 开始扫描第 {i+1}/{len(files_to_scan)} 部分: {os.path.basename(current_file)} ---", "header"))
            temp_output = f"{output_file}.part_{i+1}.tmp"
            command = [ f"./{exec_name}" if platform.system() != "Windows" else exec_name, "-pfile", current_file, "-workers", workers, "-timeout", timeout, "-output", temp_output]
            if cred_file:
                command.extend(["-cfile", cred_file])
            
            process = subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr)
            process.wait()

            # 汇总结果并清理当批次的临时结果文件
            if os.path.exists(temp_output):
                with open(output_file, 'a', encoding='utf-8') as f_out, open(temp_output, 'r', encoding='utf-8') as f_in:
                    chunk_content = f_in.read()
                    f_out.write(chunk_content)
                    total_valid_proxies += chunk_content.count('\n')
                os.remove(temp_output)
        
        print(styled(f"\n🎉 所有扫描任务成功完成! 共发现 {total_valid_proxies} 个有效代理。", "green"))
        print(styled(f"最终结果已全部保存在: {output_file}", "green"))

    except subprocess.CalledProcessError as e:
        print(styled("\n错误: Go程序编译失败。", "danger"))
        print(styled("--- 编译器输出 ---", "danger"))
        print(e.stderr)
        print(styled("--------------------", "danger"))
    except Exception as e:
        print(styled(f"\n发生未知错误: {e}", "danger"))
    finally:
        # --- 清理 ---
        print(styled("\n🧹 正在清理所有临时文件...", "blue"))
        for item in [go_source_file, exec_name, "go.mod", "go.sum"]:
            if os.path.exists(item):
                try: os.remove(item)
                except OSError: pass
        if split_was_done:
            for part_file in files_to_scan:
                if os.path.exists(part_file):
                    try: os.remove(part_file)
                    except OSError: pass
        print("清理完成。")

if __name__ == "__main__":
    main()

