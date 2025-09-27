import subprocess
import sys
import os
import platform
import shutil
import textwrap
import time

# --- Go语言源代码 (内嵌) ---
# Go代码保持不变，它专注于高效地扫描单个文件。
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

type Task struct {
	ProxyAddress string
	Username     string
	Password     string
}

type HttpbinResponse struct {
	Origin string `json:"origin"`
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime)

	proxyFile := flag.String("pfile", "", "Proxy list file path (ip:port)")
	credFile := flag.String("cfile", "", "(Optional) Credentials file path (username:password)")
	targetURL := flag.String("target", "http://httpbin.org/ip", "Validation URL")
	timeout := flag.Int("timeout", 10, "Connection timeout per proxy (seconds)")
	workers := flag.Int("workers", 100, "Number of concurrent goroutines")
	outputFile := flag.String("output", "valid_proxies.txt", "File to save valid proxies")
	flag.Parse()

	if *proxyFile == "" {
		fmt.Println("Error: Proxy file path is required. Use -pfile.")
		os.Exit(1)
	}

	proxies, err := readLines(*proxyFile)
	if err != nil {
		log.Fatalf("Could not read proxy file %s: %v", *proxyFile, err)
	}

	var credentials []string
	if *credFile != "" {
		credentials, err = readLines(*credFile)
		if err != nil {
			log.Fatalf("Could not read credentials file %s: %v", *credFile, err)
		}
	}

	var tasks []Task
	if len(credentials) > 0 {
		for _, p := range proxies {
			for _, c := range credentials {
				parts := strings.SplitN(c, ":", 2)
				if len(parts) == 2 {
					tasks = append(tasks, Task{ProxyAddress: p, Username: parts[0], Password: parts[1]})
				}
			}
		}
	} else {
		for _, p := range proxies {
			tasks = append(tasks, Task{ProxyAddress: p})
		}
	}
	log.Printf("Processing %s. Total scan tasks in this batch: %d.", *proxyFile, len(tasks))

	taskChan := make(chan Task, *workers)
	resultChan := make(chan string, len(tasks))
	var wg sync.WaitGroup

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(&wg, taskChan, resultChan, *targetURL, time.Duration(*timeout)*time.Second)
	}

	go func() {
		for _, task := range tasks {
			taskChan <- task
		}
		close(taskChan)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	log.Println("Scanning started with high-accuracy validation...")
	var validProxies []string
	outFile, err := os.Create(*outputFile)
	if err != nil {
		log.Fatalf("Could not create output file %s: %v", *outputFile, err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	for result := range resultChan {
		log.Printf("✅ High-accuracy valid proxy found: %s", result)
		validProxies = append(validProxies, result)
		fmt.Fprintln(writer, result)
		writer.Flush()
	}

	log.Printf("Batch scan complete for %s! Found %d valid proxies in this batch.", *proxyFile, len(validProxies))
}

func worker(wg *sync.WaitGroup, tasks <-chan Task, results chan<- string, targetURL string, timeout time.Duration) {
	defer wg.Done()
	for task := range tasks {
		fullProxyURL := formatProxyURL(task)
		if checkProxy(task.ProxyAddress, fullProxyURL, targetURL, timeout) {
			results <- fullProxyURL
		}
	}
}

func checkProxy(proxyAddr, proxyURLStr, targetURL string, timeout time.Duration) bool {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return false
	}
	
	proxyHost, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return false
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   timeout,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout + (5 * time.Second),
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
		return false
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	var result HttpbinResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return false
	}

	if strings.Contains(result.Origin, proxyHost) {
		return true
	}

	return false
}

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
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func formatProxyURL(task Task) string {
	if task.Username != "" && task.Password != "" {
		return fmt.Sprintf("http://%s:%s@%s", url.QueryEscape(task.Username), url.QueryEscape(task.Password), task.ProxyAddress)
	}
	return fmt.Sprintf("http://%s", task.ProxyAddress)
}
"""

# --- Python 包装器和交互逻辑 ---

def styled(message, style=""):
    """返回带样式的字符串"""
    styles = { "header": "\033[95m\033[1m", "blue": "\033[94m", "green": "\033[92m", "warning": "\033[93m\033[1m", "danger": "\033[91m\033[1m", "bold": "\033[1m", "underline": "\033[4m", "end": "\033[0m" }
    return f"{styles.get(style, '')}{message}{styles.get('end', '')}"

def check_go_installed():
    """检查Go语言环境"""
    if not shutil.which("go"):
        print(styled("\n错误: 未找到 'go' 命令。", "danger")); print("请先安装Go语言环境 (>= 1.18)。"); print("官方网站: https://golang.google.cn/dl/"); return False
    return True

def get_user_input(prompt, default_value=None):
    """获取用户输入"""
    prompt_text = f"{prompt} (默认: {default_value}): " if default_value else f"{prompt}: "
    while True:
        value = input(prompt_text) or default_value
        if value and value.strip(): return value
        if default_value is None: print(styled("输入不能为空，请重新输入。", "warning"))

def create_example_file_if_not_exists(filename, content):
    """创建示例文件"""
    if not os.path.exists(filename):
        print(styled(f"\n提示: 文件 '{filename}' 不存在，为您创建一个示例。", "blue"))
        try:
            with open(filename, "w", encoding="utf-8") as f: f.write(textwrap.dedent(content).strip() + "\n")
            print(f"示例文件 '{filename}' 创建成功。请根据需要修改其内容。")
        except IOError as e:
            print(styled(f"错误: 无法创建文件 '{filename}': {e}", "danger")); return False
    return True

# 【新】文件分割函数
def split_file(large_file_path, lines_per_chunk):
    """将大文件分割成多个小文件"""
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
        # 如果原始文件为空或没有内容，确保至少有一个空的临时文件被创建以避免后续逻辑错误
        if not chunk_files and os.path.exists(large_file_path):
             chunk_filename = f"{large_file_path}.part_1.tmp"
             open(chunk_filename, 'w').close()
             chunk_files.append(chunk_filename)
        return chunk_files
    except Exception as e:
        print(styled(f"错误: 分割文件 '{large_file_path}' 时失败: {e}", "danger"))
        return None

def main():
    print(styled("="*60, "header")); print(styled("   欢迎使用高精度HTTP代理扫描向导 (带文件分块功能)", "header")); print(styled("="*60, "header"))
    print(styled("\n重要警告:", "danger")); print("1. 本工具仅用于学习和研究网络编程，严禁用于任何非法用途。"); print("2. " + styled("未经授权对他方网络进行扫描是违法行为。", "underline") + " 请在您自己的或授权的网络环境中进行测试。"); print("3. 任何因滥用本工具导致的法律后果，由使用者自行承担。")
    
    try:
        if input("\n> " + styled("您是否理解并同意以上条款？(输入 'yes' 继续): ", "bold")).lower() != 'yes':
            print(styled("\n操作已取消。", "warning")); sys.exit(0)
    except KeyboardInterrupt: print(styled("\n操作已取消。", "warning")); sys.exit(0)

    if not check_go_installed(): sys.exit(1)

    print(styled("\n--- 第一步: 请提供代理列表文件 ---", "blue"))
    proxy_file = get_user_input("> 代理文件路径", "proxies.txt")
    create_example_file_if_not_exists(proxy_file, "# 请在此处填入代理地址, 格式为 ip:port, 每行一个")

    # 【新】交互式文件分割
    files_to_scan = [proxy_file]
    split_was_done = False
    print(styled("\n--- 第二步: 文件处理 ---", "blue"))
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

    print(styled("\n--- 第三步: 是否使用密码本? ---", "blue"))
    use_creds = get_user_input("> 是否为需要认证的代理提供密码本? (yes/no)", "no")
    cred_file = None
    if use_creds.lower() == 'yes':
        cred_file = get_user_input("> 密码本文件路径", "credentials.txt")
        create_example_file_if_not_exists(cred_file, "# 请在此处填入账号密码, 格式为 username:password, 每行一个")

    print(styled("\n--- 第四步: 配置扫描参数 ---", "blue"))
    workers = get_user_input("> 并发任务数 (推荐 50-200)", "100")
    timeout = get_user_input("> 连接超时时间 (秒)", "10")
    output_file = get_user_input("> 最终结果保存路径", "valid_proxies.txt")

    # 准备执行
    go_source_file = "scanner_temp.go"; exec_name = "scanner_exec.exe" if platform.system() == "Windows" else "scanner_exec"
    
    try:
        # 预编译Go程序
        print(styled("\n正在预编译高精度Go扫描器...", "blue"))
        with open(go_source_file, "w", encoding="utf-8") as f: f.write(GO_SOURCE_CODE)
        os.environ["GOCACHE"] = "/tmp/gocache"; os.makedirs("/tmp/gocache", exist_ok=True)
        compile_process = subprocess.run(["go", "build", "-o", exec_name, go_source_file], capture_output=True, text=True, encoding='utf-8')
        if compile_process.returncode != 0: raise subprocess.CalledProcessError(compile_process.returncode, compile_process.args, output=compile_process.stdout, stderr=compile_process.stderr)
        print(styled("预编译成功!", "green"))

        # 清空最终结果文件
        open(output_file, 'w').close()
        total_valid_proxies = 0

        # 【新】循环扫描所有文件块
        for i, current_file in enumerate(files_to_scan):
            print(styled(f"\n--- 🚀 开始扫描第 {i+1}/{len(files_to_scan)} 部分: {os.path.basename(current_file)} ---", "header"))
            temp_output = f"{output_file}.part_{i+1}.tmp"
            command = [ f"./{exec_name}" if platform.system() != "Windows" else exec_name, "-pfile", current_file, "-workers", workers, "-timeout", timeout, "-output", temp_output]
            if cred_file: command.extend(["-cfile", cred_file])
            
            process = subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr); process.wait()

            # 【新】汇总结果
            if os.path.exists(temp_output):
                with open(output_file, 'a', encoding='utf-8') as f_out, open(temp_output, 'r', encoding='utf-8') as f_in:
                    chunk_content = f_in.read()
                    f_out.write(chunk_content)
                    total_valid_proxies += chunk_content.count('\n')
                os.remove(temp_output)
        
        print(styled(f"\n🎉 所有扫描任务成功完成! 共发现 {total_valid_proxies} 个有效代理。", "green"))
        print(styled(f"最终结果已全部保存在: {output_file}", "green"))

    except subprocess.CalledProcessError as e:
        print(styled("\n错误: Go程序编译失败。", "danger")); print(styled("--- 编译器输出 ---", "danger")); print(e.stderr); print(styled("--------------------", "danger"))
    except Exception as e:
        print(styled(f"\n发生未知错误: {e}", "danger"))
    finally:
        print(styled("\n🧹 正在清理临时文件...", "blue"))
        # 清理Go相关文件
        for item in [go_source_file, exec_name, "go.mod", "go.sum"]:
            if os.path.exists(item):
                try: os.remove(item)
                except OSError: pass
        # 【新】清理分割的临时文件
        if split_was_done:
            for part_file in files_to_scan:
                if os.path.exists(part_file):
                    try: os.remove(part_file)
                    except OSError: pass
        print("清理完成。")

if __name__ == "__main__":
    main()

