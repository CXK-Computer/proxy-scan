import subprocess
import argparse
import sys
import os
import platform
import shutil
import textwrap

# --- Go 语言源代码 ---
# 将完整的Go代码作为多行字符串嵌入到Python脚本中
GO_SOURCE_CODE = r"""
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Task 结构体定义了一个扫描任务
type Task struct {
	ProxyAddress string
	Username     string
	Password     string
}

func main() {
	log.SetOutput(os.Stdout) // 将日志输出重定向到标准输出
	log.SetFlags(log.Ltime)   // 设置日志格式，只显示时间

	// --- 1. 定义和解析命令行参数 ---
	proxyFile := flag.String("pfile", "", "包含代理列表的文件路径 (格式: ip:port)")
	credFile := flag.String("cfile", "", "(可选) 包含认证信息的文件路径 (格式: username:password)")
	targetURL := flag.String("target", "http://www.baidu.com/", "用于测试代理的URL")
	timeout := flag.Int("timeout", 10, "每个代理的连接超时时间（秒）")
	workers := flag.Int("workers", 100, "并发扫描的 goroutine 数量")
	outputFile := flag.String("output", "valid_proxies.txt", "保存可用代理的结果文件")
	flag.Parse()

	if *proxyFile == "" {
		fmt.Println("错误: 必须提供代理文件路径。请使用 -pfile 参数。")
		os.Exit(1)
	}

	// --- 2. 准备扫描任务 ---
	proxies, err := readLines(*proxyFile)
	if err != nil {
		log.Fatalf("无法读取代理文件 %s: %v", *proxyFile, err)
	}

	var credentials []string
	if *credFile != "" {
		credentials, err = readLines(*credFile)
		if err != nil {
			log.Fatalf("无法读取密码本文件 %s: %v", *credFile, err)
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
	log.Printf("任务准备完成，总计 %d 个扫描任务。", len(tasks))

	// --- 3. 设置并发工作池 (Worker Pool) ---
	taskChan := make(chan Task, *workers)
	resultChan := make(chan string, len(tasks))
	var wg sync.WaitGroup

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(&wg, taskChan, resultChan, *targetURL, time.Duration(*timeout)*time.Second)
	}

	// --- 4. 分发任务并收集结果 ---
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

	log.Println("扫描开始...")
	var validProxies []string
	outFile, err := os.Create(*outputFile)
	if err != nil {
		log.Fatalf("无法创建输出文件 %s: %v", *outputFile, err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	for result := range resultChan {
		log.Printf("✅ 发现可用代理: %s", result)
		validProxies = append(validProxies, result)
		fmt.Fprintln(writer, result)
		writer.Flush()
	}

	log.Printf("扫描完成！共发现 %d 个可用代理，已保存到 %s", len(validProxies), *outputFile)
}

func worker(wg *sync.WaitGroup, tasks <-chan Task, results chan<- string, targetURL string, timeout time.Duration) {
	defer wg.Done()
	for task := range tasks {
		fullProxyURL := formatProxyURL(task)
		if checkProxy(fullProxyURL, targetURL, timeout) {
			results <- fullProxyURL
		}
	}
}

func checkProxy(proxyURLStr, targetURL string, timeout time.Duration) bool {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return false
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout + (5 * time.Second),
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 300
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

# --- 辅助函数 ---

def check_go_installed():
    """检查系统是否安装了Go"""
    if not shutil.which("go"):
        print("❌ 错误: 'go' 命令未找到。")
        print("请先安装Go语言环境 (>= 1.18) 并确保已将其添加到系统的PATH环境变量中。")
        print("官方下载地址: https://golang.google.cn/dl/")
        return False
    return True

def run_command(command, description):
    """运行一个系统命令并处理可能的错误"""
    print(f"⚙️  正在执行: {description}...")
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        # 打印标准输出（如果有的话），用于调试
        if process.stdout:
            print(process.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ 错误: {description} 失败。")
        print("--- 命令输出 ---")
        print(e.stderr)
        print("--------------------")
        return False
    except FileNotFoundError:
        print(f"❌ 错误: 命令 '{command[0]}' 未找到。")
        return False
    except Exception as e:
        print(f"❌ 发生未知错误: {e}")
        return False

def create_example_file_if_not_exists(filename, content):
    """如果文件不存在，则创建示例文件"""
    if not os.path.exists(filename):
        print(f"ℹ️  提示: 未找到 '{filename}'，正在为您创建一个示例文件。")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(textwrap.dedent(content).strip())

# --- 主函数 ---

def main():
    """主函数，用于解析参数和运行扫描器"""
    parser = argparse.ArgumentParser(
        description="HTTP代理扫描器 (Python一体化包装脚本)。",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-p", "--proxies",
        required=True,
        help="[必需] 包含代理列表的文件路径 (格式: ip:port)"
    )
    parser.add_argument(
        "-c", "--creds",
        default=None,
        help="[可选] 包含认证信息的文件路径 (格式: username:password)"
    )
    parser.add_argument(
        "-t", "--target",
        default="http://www.baidu.com/",
        help="用于测试代理的目标URL (默认: http://www.baidu.com/)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="每个代理的连接超时时间（秒）(默认: 10)"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=100,
        help="并发扫描的线程数 (默认: 100)"
    )
    parser.add_argument(
        "-o", "--output",
        default="valid_proxies.txt",
        help="保存可用代理的结果文件 (默认: valid_proxies.txt)"
    )

    args = parser.parse_args()

    # --- 1. 环境检查 ---
    if not check_go_installed():
        sys.exit(1)

    # --- 2. 准备文件 ---
    go_source_file = "proxyscanner.go"
    if platform.system() == "Windows":
        executable_name = "proxyscanner.exe"
    else:
        executable_name = "proxyscanner"

    # 创建示例输入文件
    create_example_file_if_not_exists(
        args.proxies,
        """
        # 这是一个示例代理文件，请将代理地址(ip:port)填入此处
        # 以 '#' 开头的行将被视为注释并忽略
        112.85.174.198:9999
        121.232.148.118:9000
        """
    )
    if args.creds:
        create_example_file_if_not_exists(
            args.creds,
            """
            # 这是一个示例密码本文件，格式为 username:password
            # 程序会尝试用这里的每一组账号密码去登录代理列表中的每一个代理
            user1:pass123
            admin:password
            """
        )

    # 将Go代码写入临时文件
    try:
        with open(go_source_file, "w", encoding="utf-8") as f:
            f.write(GO_SOURCE_CODE)
    except IOError as e:
        print(f"❌ 错误: 无法写入Go源文件 '{go_source_file}': {e}")
        sys.exit(1)

    # --- 3. 准备并编译Go程序 ---
    cleanup_list = [go_source_file, executable_name, "go.mod", "go.sum"]
    
    try:
        if not run_command(["go", "mod", "init", "proxyscanner"], "初始化Go模块"):
            raise SystemExit()
        if not run_command(["go", "mod", "tidy"], "整理Go模块依赖"):
             raise SystemExit()
        if not run_command(["go", "build", "-o", executable_name, go_source_file], "编译Go程序"):
            raise SystemExit()

        # --- 4. 构建并执行Go程序的命令 ---
        executable_path = f"./{executable_name}" if platform.system() != "Windows" else executable_name

        command = [
            executable_path,
            "-pfile", args.proxies,
            "-target", args.target,
            "-timeout", str(args.timeout),
            "-workers", str(args.workers),
            "-output", args.output,
        ]
        if args.creds:
            command.extend(["-cfile", args.creds])

        print("\n" + "="*50)
        print("🚀 开始执行Go扫描器 (实时日志如下)")
        print("="*50 + "\n")

        # 实时流式输出Go程序的日志
        process = subprocess.Popen(command, stdout=sys.stdout, stderr=sys.stderr)
        process.wait()

        if process.returncode == 0:
            print("\n" + "="*50)
            print("🎉 扫描任务成功完成!")
            print(f"🔍 结果已保存在: {args.output}")
            print("="*50)
        else:
            print(f"\n⚠️ 扫描任务执行出错，退出码: {process.returncode}")

    except (SystemExit, KeyboardInterrupt):
        print("\n🔴 操作被中断。")
    finally:
        # --- 5. 清理临时文件 ---
        print("\n🧹  正在清理临时文件...")
        for item in cleanup_list:
            if os.path.exists(item):
                try:
                    os.remove(item)
                except OSError as e:
                    print(f"无法删除 {item}: {e}")
        print("清理完成。")


if __name__ == "__main__":
    main()
