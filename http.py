import subprocess
import sys
import os
import platform
import shutil
import textwrap
import time

# --- Go语言源代码 (内嵌) ---
# 【重大升级】重写了checkProxy函数，使用httpbin.org进行IP回显验证，确保代理的真实有效性。
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

// 【新】用于解析httpbin.org返回的JSON
type HttpbinResponse struct {
	Origin string `json:"origin"`
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime)

	proxyFile := flag.String("pfile", "", "Proxy list file path (ip:port)")
	credFile := flag.String("cfile", "", "(Optional) Credentials file path (username:password)")
	// 【新】默认验证目标更新为httpbin.org/ip
	targetURL := flag.String("target", "http://httpbin.org/ip", "Validation URL for checking proxy's public IP")
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
	log.Printf("Tasks ready. Total scan tasks: %d.", len(tasks))

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

	log.Printf("Scan complete! Found %d valid proxies. Saved to %s", len(validProxies), *outputFile)
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

// 【重大升级】全新的、高精度的代理验证函数
func checkProxy(proxyAddr, proxyURLStr, targetURL string, timeout time.Duration) bool {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return false
	}
	
	proxyHost, _, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		return false // 必须是 ip:port 格式
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
		// 响应不是有效的JSON，说明目标不是httpbin，判定为无效代理
		return false
	}

	// 检查httpbin返回的IP是否包含代理服务器自身的IP
	// httpbin可能会返回一个逗号分隔的IP列表（例如通过X-Forwarded-For），所以我们用Contains
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

# --- Python 包装器和交互逻辑 (保持不变) ---

def styled(message, style=""):
    """返回带样式的字符串"""
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
    start_style = styles.get(style, "")
    end_style = styles.get("end", "")
    return f"{start_style}{message}{end_style}"

def check_go_installed():
    """检查Go语言环境"""
    if not shutil.which("go"):
        print(styled("\n错误: 未找到 'go' 命令。", "danger"))
        print("请先安装Go语言环境 (>= 1.18)。")
        print("官方网站: https://golang.google.cn/dl/")
        return False
    return True

def get_user_input(prompt, default_value=None):
    """获取用户输入"""
    if default_value:
        return input(f"{prompt} (默认: {default_value}): ") or default_value
    else:
        while True:
            value = input(f"{prompt}: ")
            if value.strip():
                return value
            print(styled("输入不能为空，请重新输入。", "warning"))

def create_example_file_if_not_exists(filename, content):
    """创建示例文件"""
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

def main():
    """主函数，交互式设置并运行扫描器"""
    print(styled("="*60, "header"))
    print(styled("   欢迎使用高精度HTTP代理扫描向导", "header"))
    print(styled("="*60, "header"))

    print(styled("\n重要警告:", "danger"))
    print("1. 本工具仅用于学习和研究网络编程，严禁用于任何非法用途。")
    warning_message = "2. " + styled("未经授权对他方网络进行扫描是违法行为。", "underline") + " 请在您自己的或授权的网络环境中进行测试。"
    print(warning_message)
    print("3. 任何因滥用本工具导致的法律后果，由使用者自行承担。")
    
    try:
        confirm = input("\n> " + styled("您是否理解并同意以上条款？(输入 'yes' 继续): ", "bold"))
        if confirm.lower() != 'yes':
            print(styled("\n操作已取消。", "warning"))
            sys.exit(0)
    except KeyboardInterrupt:
        print(styled("\n操作已取消。", "warning"))
        sys.exit(0)

    if not check_go_installed():
        sys.exit(1)

    print(styled("\n--- 第一步: 请提供代理列表文件 ---", "blue"))
    proxy_file = get_user_input("> 代理文件路径", "proxies.txt")
    create_example_file_if_not_exists(proxy_file, "# 请在此处填入代理地址, 格式为 ip:port, 每行一个")

    print(styled("\n--- 第二步: 是否使用密码本? ---", "blue"))
    use_creds = get_user_input("> 是否为需要认证的代理提供密码本? (yes/no)", "no")
    
    cred_file = None
    if use_creds.lower() == 'yes':
        cred_file = get_user_input("> 密码本文件路径", "credentials.txt")
        create_example_file_if_not_exists(cred_file, "# 请在此处填入账号密码, 格式为 username:password, 每行一个")

    print(styled("\n--- 第三步: 配置扫描参数 ---", "blue"))
    workers = get_user_input("> 并发任务数 (推荐 50-200)", "100")
    timeout = get_user_input("> 连接超时时间 (秒)", "10")
    output_file = get_user_input("> 结果保存路径", "valid_proxies.txt")

    print("\n" + styled("="*25 + " 配置确认 " + "="*25, "green"))
    print(f"  代理列表文件: {proxy_file}")
    print(f"  密码本文件:   {cred_file if cred_file else '(不使用)'}")
    print(f"  并发任务数:   {workers}")
    print(f"  超时时间:     {timeout} 秒")
    print(f"  结果输出文件: {output_file}")
    print(styled("="*60, "green"))

    try:
        start_scan = input("\n> " + styled("是否开始扫描? (yes/no): ", "bold"))
        if start_scan.lower() != 'yes':
            print(styled("\n操作已取消。", "warning"))
            sys.exit(0)
    except KeyboardInterrupt:
        print(styled("\n操作已取消。", "warning"))
        sys.exit(0)

    go_source_file = "scanner_temp.go"
    exec_name = "scanner_exec.exe" if platform.system() == "Windows" else "scanner_exec"
    
    try:
        go_cache_path = "/tmp/gocache"
        os.environ["GOCACHE"] = go_cache_path
        os.makedirs(go_cache_path, exist_ok=True)
        print(styled(f"\n提示: 已自动设置Go编译缓存目录为: {go_cache_path}", "blue"))

        with open(go_source_file, "w", encoding="utf-8") as f:
            f.write(GO_SOURCE_CODE)

        print(styled("正在编译高精度Go扫描器...", "blue"))
        compile_process = subprocess.run(
            ["go", "build", "-o", exec_name, go_source_file],
            capture_output=True, text=True, encoding='utf-8'
        )
        if compile_process.returncode != 0:
            raise subprocess.CalledProcessError(
                compile_process.returncode, compile_process.args,
                output=compile_process.stdout, stderr=compile_process.stderr
            )
        print(styled("编译成功!", "green"))

        command = [
            f"./{exec_name}" if platform.system() != "Windows" else exec_name,
            "-pfile", proxy_file, "-workers", workers,
            "-timeout", timeout, "-output", output_file,
        ]
        if cred_file:
            command.extend(["-cfile", cred_file])
        
        print(styled("\n--- 🚀 开始执行高精度扫描 (实时日志) ---", "header"))
        process = subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr)
        process.wait()

        if process.returncode == 0:
            print(styled("\n🎉 扫描任务成功完成!", "green"))
        else:
            print(styled(f"\n⚠️ 扫描任务执行出错，退出码: {process.returncode}", "warning"))

    except subprocess.CalledProcessError as e:
        print(styled("\n错误: Go程序编译失败。", "danger"))
        print(styled("--- 编译器输出 ---", "danger"))
        print(e.stderr)
        print(styled("--------------------", "danger"))
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

