import subprocess
import sys
import tempfile
import os
import shutil
import re
import math

# --- GO 语言核心代码 1: 全功能认证扫描器 ---
# 负责使用密码本进行登录尝试，功能保持不变
GO_SOURCE_CODE_SCANNER = r'''
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Creds struct { Username string; Password string }
func checkProxyAuth(host string, port string, creds Creds, timeout time.Duration) {
	target := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.DialTimeout("tcp", target, timeout); if err != nil { return }
	defer conn.Close()
	_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); if err != nil { return }
	reply := make([]byte, 2); _, err = conn.Read(reply)
	if err != nil || reply[0] != 0x05 { return }
	switch reply[1] {
	case 0x00:
		if creds.Username == "" && creds.Password == "" { fmt.Printf("[+] 成功: %s (无需认证)\n", target) }
	case 0x02:
		if creds.Username == "" && creds.Password == "" { return }
		userBytes, passBytes := []byte(creds.Username), []byte(creds.Password)
		req := append([]byte{0x01, byte(len(userBytes))}, userBytes...)
		req = append(req, byte(len(passBytes))); req = append(req, passBytes...)
		_, err = conn.Write(req); if err != nil { return }
		authReply := make([]byte, 2); _, err = conn.Read(authReply)
		if err == nil && authReply[0] == 0x01 && authReply[1] == 0x00 {
			fmt.Printf("[+] 成功: %s - 用户名: %s - 密码: %s\n", target, creds.Username, creds.Password)
		}
	}
}
func fileToLines(path string) ([]string, error) {
	file, err := os.Open(path); if err != nil { return nil, err }; defer file.Close()
	var lines []string; scanner := bufio.NewScanner(file)
	for scanner.Scan() { lines = append(lines, scanner.Text()) }
	return lines, scanner.Err()
}
func main() {
	proxyFile := flag.String("proxyFile", "", ""); dictFile := flag.String("dictFile", "", "")
	threads := flag.Int("threads", 100, ""); timeout := flag.Int("timeout", 5, "")
	flag.Parse()
	var credentials []Creds
	if *dictFile != "" {
		dictLines, _ := fileToLines(*dictFile)
		for _, line := range dictLines {
			parts := strings.Fields(line)
			if len(parts) == 2 { credentials = append(credentials, Creds{parts[0], parts[1]}) } else {
				parts = strings.SplitN(line, ":", 2)
				if len(parts) == 2 { credentials = append(credentials, Creds{parts[0], parts[1]}) }
			}
		}
	} else { credentials = append(credentials, Creds{"", ""}) }
	
	proxies, _ := fileToLines(*proxyFile); var wg sync.WaitGroup
	sem := make(chan struct{}, *threads)
	for _, proxy := range proxies {
		parts := strings.Split(proxy, ":"); if len(parts) != 2 { continue }
		for _, cred := range credentials {
			wg.Add(1); sem <- struct{}{}
			go func(h, p string, c Creds) {
				defer wg.Done(); defer func(){ <-sem }()
				checkProxyAuth(h, p, c, time.Duration(*timeout)*time.Second)
			}(parts[0], parts[1], cred)
		}
	}
	wg.Wait()
}
'''

# --- GO 语言核心代码 2: SOCKS5 代理筛选器 ---
# 负责净化代理列表，功能保持不变
GO_SOURCE_CODE_FILTER = r'''
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func isSocks5(target string, timeout time.Duration, results chan<- string) {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		results <- ""
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		results <- ""
		return
	}

	resp := make([]byte, 2)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(resp)
	if err != nil || n != 2 || resp[0] != 0x05 {
		results <- ""
		return
	}
	results <- target
}

func main() {
	inputFile := flag.String("inputFile", "", "输入的原始代理文件")
	outputFile := flag.String("outputFile", "", "输出筛选结果的文件")
	threads := flag.Int("threads", 200, "并发线程数")
	timeout := flag.Int("timeout", 5, "连接超时 (秒)")
	flag.Parse()

	if *inputFile == "" || *outputFile == "" {
		fmt.Println("错误: 必须提供输入和输出文件路径。")
		os.Exit(1)
	}

	file, err := os.Open(*inputFile)
	if err != nil {
		fmt.Printf("错误: 无法打开输入文件: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var targets []string
	for scanner.Scan() { targets = append(targets, strings.TrimSpace(scanner.Text())) }
	
	total := len(targets)
	fmt.Printf("开始筛选 %d 个代理...\n", total)

	var wg sync.WaitGroup
	results := make(chan string, total)
	sem := make(chan struct{}, *threads)
	
	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			isSocks5(t, time.Duration(*timeout)*time.Second, results)
			<-sem
		}(target)
	}

	wg.Wait()
	close(results)

	var validProxies []string
	for r := range results {
		if r != "" {
			validProxies = append(validProxies, r)
		}
	}

	outFile, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("错误: 无法创建输出文件: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	for _, proxy := range validProxies { fmt.Fprintln(writer, proxy) }
	writer.Flush()
		
	fmt.Printf("筛选完成！从 %d 个目标中发现 %d 个有效的SOCKS5代理。\n", total, len(validProxies))
	fmt.Printf("结果已保存至: %s\n", *outputFile)
}
'''

# --- Python 交互式包装器 (集成式工作流) ---

def print_header(title):
    print("\n" + "="*50); print(f"--- {title} ---"); print("="*50)

def get_validated_input(prompt, validation_func, error_message):
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input): return user_input
        else: print(f"输入错误: {error_message}")

def validate_file_exists(path): return os.path.exists(path)
def validate_positive_integer(num_str): return num_str.isdigit() and int(num_str) > 0

def run_go_command(args_list, go_source_code):
    if not shutil.which("go"):
        print("\n错误: 未找到 'go' 命令。请先安装 Go 语言环境。")
        return
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp(prefix="socks5_toolkit_")
        go_file_path = os.path.join(temp_dir, "main.go")
        with open(go_file_path, "w", encoding="utf-8") as f: f.write(go_source_code)
        cmd = ["go", "run", go_file_path] + args_list
        print("\n--- 正在启动 Go 核心引擎 ---")
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace'
        )
        for line in iter(process.stdout.readline, ''): print(line.strip())
        process.wait()
        print("--- 任务执行完毕 ---")
    except Exception as e: print(f"发生了一个意外错误: {e}")
    finally:
        if temp_dir and os.path.exists(temp_dir): shutil.rmtree(temp_dir)

def ask_and_split_file(input_path):
    """询问用户是否分割文件，并执行分割操作，返回待处理的文件列表"""
    choice = input(f"文件 '{os.path.basename(input_path)}' 包含大量代理吗？是否需要将其分割成多个小文件再处理? (y/n): ").lower()
    if choice != 'y':
        return [input_path] # 用户不分割，返回原始文件路径的列表
    
    lines_per_file_str = get_validated_input("请输入每个小文件的行数 (默认1000): ", lambda x: x=="" or validate_positive_integer(x), "请输入正整数。") or "1000"
    try:
        with open(input_path, 'r', encoding='utf-8') as f: lines = f.readlines()
        if not lines: 
            print("文件为空，无需分割。"); return [input_path]
        
        total_lines, lines_per_file = len(lines), int(lines_per_file_str)
        if total_lines <= lines_per_file:
            print("文件行数少于或等于单个文件行数，无需分割。"); return [input_path]

        num_files = math.ceil(total_lines / lines_per_file)
        print(f"\n总计 {total_lines} 行，将被分割成 {num_files} 个文件。")
        file_base, file_ext = os.path.splitext(input_path)
        
        new_file_paths = []
        for i in range(num_files):
            output_path = f"{file_base}_part_{i+1}{file_ext}"
            with open(output_path, 'w', encoding='utf-8') as f_out:
                f_out.writelines(lines[i*lines_per_file:(i+1)*lines_per_file])
            print(f"已生成文件: {output_path}")
            new_file_paths.append(output_path)
        return new_file_paths
    except Exception as e: 
        print(f"处理文件时出错: {e}"); return [input_path]

def handle_full_scan():
    print_header("全功能认证扫描")
    print("此功能将使用密码本尝试登录有效的SOCKS5代理。")
    proxy_file = get_validated_input("请输入代理文件路径: ", validate_file_exists, "文件不存在。")
    
    files_to_scan = ask_and_split_file(proxy_file)

    use_dict = input("是否使用密码本进行扫描? (y/n, 否则只检查无认证代理): ").lower()
    dict_file = None
    if use_dict == 'y': dict_file = get_validated_input("请输入密码本文件路径: ", validate_file_exists, "文件不存在。")
    
    threads = get_validated_input("并发线程数 (默认100): ", lambda x: x=="" or validate_positive_integer(x), "请输入正整数。") or "100"
    timeout = get_validated_input("连接超时(秒, 默认5): ", lambda x: x=="" or validate_positive_integer(x), "请输入正整数。") or "5"

    for file_path in files_to_scan:
        print(f"\n--- 正在扫描文件: {os.path.basename(file_path)} ---")
        cmd_args = ["-proxyFile", file_path, "-threads", threads, "-timeout", timeout]
        if dict_file: cmd_args.extend(["-dictFile", dict_file])
        run_go_command(cmd_args, GO_SOURCE_CODE_SCANNER)

def handle_proxy_filtering():
    print_header("筛选SOCKS5代理 (净化列表)")
    print("此功能将剔除非SOCKS5服务，并将有效的代理保存到新文件。")
    input_file = get_validated_input("请输入原始代理文件路径: ", validate_file_exists, "文件不存在。")

    files_to_filter = ask_and_split_file(input_file)

    threads = get_validated_input("并发线程数 (默认200): ", lambda x: x=="" or validate_positive_integer(x), "请输入正整数。") or "200"
    timeout = get_validated_input("连接超时(秒, 默认5): ", lambda x: x=="" or validate_positive_integer(x), "请输入正整数。") or "5"
    
    for file_path in files_to_filter:
        print(f"\n--- 正在筛选文件: {os.path.basename(file_path)} ---")
        base, ext = os.path.splitext(file_path)
        output_file = f"{base}_valid{ext}"
        print(f"筛选结果将保存至: {output_file}")
        
        cmd_args = ["-inputFile", file_path, "-outputFile", output_file, "-threads", threads, "-timeout", timeout]
        run_go_command(cmd_args, GO_SOURCE_CODE_FILTER)

def main_menu():
    print("\n" + "*"*60)
    print(" " * 12 + "SOCKS5 集成式工作流程工具箱 (最终版)")
    print("*"*60)
    while True:
        print("\n--- 主菜单 ---")
        print("  [1] 全功能认证扫描 (尝试登录)")
        print("  [2] 筛选SOCKS5代理 (净化列表)")
        print("  [3] 退出程序")
        choice = input("\n请输入您的选择 [1-3]: ")
        if choice == '1': handle_full_scan()
        elif choice == '2': handle_proxy_filtering()
        elif choice == '3': print("感谢使用，再见！"); break
        else: print("无效的输入，请输入 1 到 3 之间的数字。")
        input("\n按 Enter 键返回主菜单...")

if __name__ == "__main__":
    main_menu()

