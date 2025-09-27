import subprocess
import sys
import os
import platform
import shutil
import textwrap
import time

# --- Go语言源代码 (内嵌) ---
# 【重大优化】增加了从标准输入(stdin)读取代理列表的功能。
# 现在Go程序可以不依赖文件，直接接收来自其他程序（如Python）的数据流。
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

// 【新】从标准输入读取内容的函数
func readLinesFromStdin() ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func readLinesFromFile(path string) ([]string, error) {
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

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime)

	proxyFile := flag.String("pfile", "", "代理列表文件路径 (如果为空, 则从标准输入读取)")
	credFile := flag.String("cfile", "", "(可选) 认证信息文件路径")
	targetURL := flag.String("target", "http://httpbin.org/ip", "验证URL")
	timeout := flag.Int("timeout", 10, "超时时间 (秒)")
	workers := flag.Int("workers", 100, "并发协程数")
	outputFile := flag.String("output", "valid_proxies.txt", "结果输出文件")
	flag.Parse()

	var proxies []string
	var err error

	// 【修改】根据-pfile参数是否提供，决定数据来源
	if *proxyFile != "" {
		log.Printf("从文件 %s 读取代理列表...", *proxyFile)
		proxies, err = readLinesFromFile(*proxyFile)
	} else {
		log.Println("从标准输入 (stdin) 读取代理列表...")
		proxies, err = readLinesFromStdin()
	}
	if err != nil {
		log.Fatalf("读取代理列表失败: %v", err)
	}

	var credentials []string
	if *credFile != "" {
		credentials, err = readLinesFromFile(*credFile)
		if err != nil {
			log.Fatalf("读取认证文件 %s 失败: %v", *credFile, err)
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
	log.Printf("本批次总扫描任务数: %d。", len(tasks))

	taskChan := make(chan Task, *workers)
	resultChan := make(chan string, len(tasks))
	var wg sync.WaitGroup

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(&wg, taskChan, resultChan, *targetURL, time.Duration(*timeout)*time.Second)
	}

	go func() {
		for _, task := range tasks { taskChan <- task }
		close(taskChan)
	}()
	go func() { wg.Wait(); close(resultChan) }()

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
		writer.Flush()
	}
	log.Printf("本批次扫描完成！发现 %d 个有效代理。", len(validProxies))
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
	proxyURL, err := url.Parse(proxyURLStr); if err != nil { return false }
	proxyHost, _, err := net.SplitHostPort(proxyAddr); if err != nil { return false }
	transport := &http.Transport{ Proxy: http.ProxyURL(proxyURL), DialContext: (&net.Dialer{ Timeout: timeout }).DialContext, TLSHandshakeTimeout: timeout, }
	client := &http.Client{ Transport: transport, Timeout: timeout + (5 * time.Second), }
	req, err := http.NewRequest("GET", targetURL, nil); if err != nil { return false }
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	resp, err := client.Do(req); if err != nil { return false }; defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return false }
	body, err := ioutil.ReadAll(resp.Body); if err != nil { return false }
	var result HttpbinResponse
	if err := json.Unmarshal(body, &result); err != nil { return false }
	if strings.Contains(result.Origin, proxyHost) { return true }
	return false
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
    styles = { "header": "\033[95m\033[1m", "blue": "\033[94m", "green": "\033[92m", "warning": "\033[93m\033[1m", "danger": "\033[91m\033[1m", "bold": "\033[1m", "underline": "\033[4m", "end": "\033[0m" }
    return f"{styles.get(style, '')}{message}{styles.get('end', '')}"

def get_user_input(prompt, default_value=None):
    prompt_text = f"{prompt} (默认: {default_value}): " if default_value else f"{prompt}: "
    while True:
        value = input(prompt_text) or default_value
        if value and value.strip(): return value
        if default_value is None: print(styled("输入不能为空，请重新输入。", "warning"))

def create_example_file_if_not_exists(filename, content):
    if not os.path.exists(filename):
        print(styled(f"\n提示: 文件 '{filename}' 不存在，为您创建一个示例。", "blue"))
        try:
            with open(filename, "w", encoding="utf-8") as f: f.write(textwrap.dedent(content).strip() + "\n")
            print(f"示例文件 '{filename}' 创建成功。")
        except IOError as e:
            print(styled(f"错误: 无法创建文件 '{filename}': {e}", "danger")); return False
    return True

def find_go_executable():
    if shutil.which("go"): return shutil.which("go")
    common_paths = ["/usr/local/go/bin/go", "/usr/bin/go", "/snap/bin/go", os.path.expanduser("~/go/bin/go")]
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            print(styled(f"在标准路径中找到Go: {path}", "green")); return path
    print(styled("\n错误: 自动查找 'go' 命令失败。", "danger"))
    while True:
        manual_path = input("> " + styled("请手动输入 'go' 命令的完整路径: ", "bold"))
        if manual_path and os.path.exists(manual_path) and os.access(manual_path, os.X_OK): return manual_path
        else: print(styled(f"路径 '{manual_path}' 无效，请重新输入。", "warning"))

def main():
    print(styled("="*60, "header")); print(styled("   欢迎使用高精度HTTP代理扫描向导 (高性能IO版)", "header")); print(styled("="*60, "header"))
    
    go_cmd = find_go_executable()
    if not go_cmd: sys.exit(1)
    print(styled(f"将使用Go命令进行编译: {go_cmd}", "green"))

    print(styled("\n重要警告:", "danger")); print("1. 本工具仅用于学习和研究..."); print("2. " + styled("未经授权...", "underline")); print("3. 任何因滥用...")
    try:
        if input("\n> " + styled("您是否理解并同意以上条款？(输入 'yes' 继续): ", "bold")).lower() != 'yes':
            print(styled("\n操作已取消。", "warning")); sys.exit(0)
    except KeyboardInterrupt: print(styled("\n操作已取消。", "warning")); sys.exit(0)

    print(styled("\n--- 第一步: 代理文件 ---", "blue"))
    proxy_file = get_user_input("> 请输入代理文件路径", "proxies.txt")
    create_example_file_if_not_exists(proxy_file, "# ip:port")

    print(styled("\n--- 第二步: 处理方式 ---", "blue"))
    use_chunking = get_user_input("> 是否以分块方式处理大文件 (推荐, 可节省内存)? (yes/no)", "yes").lower() == 'yes'
    lines_per_chunk = 0
    if use_chunking:
        lines_per_chunk = int(get_user_input("> 每个内存块包含多少行代理?", "5000"))

    print(styled("\n--- 第三步: 密码本 ---", "blue"))
    cred_file = None
    if get_user_input("> 是否使用密码本? (yes/no)", "no").lower() == 'yes':
        cred_file = get_user_input("> 请输入密码本文件路径", "credentials.txt")
        create_example_file_if_not_exists(cred_file, "# username:password")

    print(styled("\n--- 第四步: 扫描参数 ---", "blue"))
    workers = get_user_input("> 请输入并发任务数", "100")
    timeout = get_user_input("> 请输入超时时间 (秒)", "10")
    output_file = get_user_input("> 请输入最终结果保存路径", "valid_proxies.txt")

    go_source_file = "scanner_temp.go"; exec_name = "scanner_exec.exe" if platform.system() == "Windows" else "scanner_exec"
    try:
        print(styled("\n正在预编译高精度Go扫描器...", "blue"))
        with open(go_source_file, "w", encoding="utf-8") as f: f.write(GO_SOURCE_CODE)
        os.environ["GOCACHE"] = "/tmp/gocache"; os.makedirs("/tmp/gocache", exist_ok=True)
        compile_process = subprocess.run([go_cmd, "build", "-o", exec_name, go_source_file], capture_output=True, text=True, encoding='utf-8')
        if compile_process.returncode != 0: raise subprocess.CalledProcessError(compile_process.returncode, compile_process.args, output=compile_process.stdout, stderr=compile_process.stderr)
        print(styled("预编译成功!", "green"))

        open(output_file, 'w').close(); total_valid_proxies = 0

        # 【重大修改】根据用户选择，决定处理方式
        if not use_chunking:
            # --- 方式一: 一次性处理整个文件 ---
            print(styled(f"\n--- 🚀 开始完整扫描文件: {proxy_file} ---", "header"))
            command = [ f"./{exec_name}" if platform.system() != "Windows" else exec_name, "-pfile", proxy_file, "-workers", workers, "-timeout", timeout, "-output", output_file]
            if cred_file: command.extend(["-cfile", cred_file])
            subprocess.run(command, check=True)
            with open(output_file, 'r', encoding='utf-8') as f: total_valid_proxies = f.read().count('\n')

        else:
            # --- 方式二: 高效内存分块处理 ---
            print(styled("\n--- 🚀 开始以内存分块方式进行扫描 ---", "header"))
            chunk_count = 0
            with open(proxy_file, 'r', encoding='utf-8', errors='ignore') as f:
                while True:
                    chunk_count += 1
                    lines = [next(f).strip() for _ in range(lines_per_chunk) if f]
                    chunk = [line for line in lines if line] # 过滤掉可能的空行
                    if not chunk: break # 如果块为空，说明文件已读完
                    
                    print(styled(f"\n--- 正在处理第 {chunk_count} 数据块 ({len(chunk)} 行) ---", "blue"))
                    
                    # 将块数据编码后通过 stdin 传递
                    chunk_data = "\n".join(chunk).encode('utf-8')
                    temp_output = f"{output_file}.part_{chunk_count}.tmp"
                    command = [f"./{exec_name}", "-workers", workers, "-timeout", timeout, "-output", temp_output] # 注意：这里不传-pfile
                    if cred_file: command.extend(["-cfile", cred_file])
                    
                    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=sys.stdout, stderr=sys.stderr)
                    process.communicate(input=chunk_data)

                    if os.path.exists(temp_output):
                        with open(output_file, 'a', encoding='utf-8') as f_out, open(temp_output, 'r', encoding='utf-8') as f_in:
                            chunk_content = f_in.read(); f_out.write(chunk_content)
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
        for item in [go_source_file, exec_name, "go.mod", "go.sum"]:
            if os.path.exists(item):
                try: os.remove(item)
                except OSError: pass
        print("清理完成。")

if __name__ == "__main__":
    main()

