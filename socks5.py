import subprocess
import sys
import tempfile
import os
import shutil
import re
import math

# --- GO 语言核心代码 ---
# 这部分代码保持不变，因为它通过命令行标志接收输入，非常适合被包装调用。
GO_SOURCE_CODE = r'''
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Creds struct {
	Username string
	Password string
}

func checkProxy(host string, port string, creds Creds, timeout time.Duration) {
	target := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	if err != nil {
		return
	}

	reply := make([]byte, 2)
	_, err = conn.Read(reply)
	if err != nil || reply[0] != 0x05 {
		return
	}

	switch reply[1] {
	case 0x00:
		if creds.Username == "" && creds.Password == "" {
			fmt.Printf("[+] 成功: %s (无需认证)\n", target)
		}
	case 0x02:
		if creds.Username == "" && creds.Password == "" {
			return
		}
		userBytes := []byte(creds.Username)
		passBytes := []byte(creds.Password)
		req := []byte{0x01, byte(len(userBytes))}
		req = append(req, userBytes...)
		req = append(req, byte(len(passBytes)))
		req = append(req, passBytes...)

		_, err = conn.Write(req)
		if err != nil {
			return
		}

		authReply := make([]byte, 2)
		_, err = conn.Read(authReply)
		if err != nil || authReply[0] != 0x01 || authReply[1] != 0x00 {
			return
		}
		fmt.Printf("[+] 成功: %s - 用户名: %s - 密码: %s\n", target, creds.Username, creds.Password)
	}
}

func fileToLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func main() {
	proxyFile := flag.String("proxyFile", "", "代理列表文件 (格式: host:port)")
	dictFile := flag.String("dictFile", "", "密码本文件 (格式: user:pass)")
	target := flag.String("target", "", "单个代理目标 (格式: host:port)")
	creds := flag.String("creds", "", "单个目标的凭证 (格式: user:pass)")
	threads := flag.Int("threads", 100, "并发线程数")
	timeout := flag.Int("timeout", 5, "连接超时时间 (秒)")
	flag.Parse()

	if *target != "" {
		host, port, err := net.SplitHostPort(*target)
		if err != nil {
			fmt.Printf("错误: 无效的目标格式: %v\n", err)
			os.Exit(1)
		}
		
		var credentials []Creds
		if *creds != "" {
			parts := strings.SplitN(*creds, ":", 2)
			if len(parts) == 2 {
				credentials = append(credentials, Creds{Username: parts[0], Password: parts[1]})
			}
		} else if *dictFile != "" {
            dictLines, _ := fileToLines(*dictFile)
            for _, line := range dictLines {
                parts := strings.Fields(line)
                if len(parts) == 2 { credentials = append(credentials, Creds{Username: parts[0], Password: parts[1]}) } else {
                    parts = strings.SplitN(line, ":", 2)
                    if len(parts) == 2 { credentials = append(credentials, Creds{Username: parts[0], Password: parts[1]}) }
                }
            }
        } else {
			credentials = append(credentials, Creds{Username: "", Password: ""})
		}

        for _, c := range credentials {
            checkProxy(host, port, c, time.Duration(*timeout)*time.Second)
        }

	} else if *proxyFile != "" {
		proxies, _ := fileToLines(*proxyFile)
		var credentials []Creds
		if *dictFile != "" {
			dictLines, _ := fileToLines(*dictFile)
			for _, line := range dictLines {
				parts := strings.Fields(line)
                if len(parts) == 2 { credentials = append(credentials, Creds{Username: parts[0], Password: parts[1]}) } else {
                    parts = strings.SplitN(line, ":", 2)
                    if len(parts) == 2 { credentials = append(credentials, Creds{Username: parts[0], Password: parts[1]}) }
                }
			}
		} else {
			credentials = append(credentials, Creds{Username: "", Password: ""})
		}
		
		var wg sync.WaitGroup
		sem := make(chan struct{}, *threads)
		for _, proxy := range proxies {
			parts := strings.Split(proxy, ":")
			if len(parts) != 2 { continue }
			host, port := parts[0], parts[1]
			for _, cred := range credentials {
				wg.Add(1)
				sem <- struct{}{}
				go func(h, p string, c Creds) {
					defer wg.Done(); defer func(){ <-sem }()
					checkProxy(h, p, c, time.Duration(*timeout)*time.Second)
				}(host, port, cred)
			}
		}
		wg.Wait()
	}
}
'''

# --- Python 交互式包装器 ---

def print_header(title):
    """打印带有标题的分割线"""
    print("\n" + "="*50)
    print(f"--- {title} ---")
    print("="*50)

def get_validated_input(prompt, validation_func, error_message):
    """循环获取输入，直到通过验证函数"""
    while True:
        user_input = input(prompt).strip()
        if validation_func(user_input):
            return user_input
        else:
            print(f"输入错误: {error_message}")

def validate_file_exists(path):
    """验证文件是否存在"""
    return os.path.exists(path)

def validate_target_format(target_str):
    """验证 'host:port' 格式"""
    # 简单的正则，匹配 IPv4/域名 和端口
    return re.match(r"^[a-zA-Z0-9\.\-]+:\d{1,5}$", target_str) is not None

def validate_creds_format(creds_str):
    """验证 'user:pass' 格式"""
    return ":" in creds_str

def validate_positive_integer(num_str):
    """验证是否为正整数"""
    return num_str.isdigit() and int(num_str) > 0

def run_go_command(args_list):
    """编译并运行内嵌的Go程序，传递参数"""
    if not shutil.which("go"):
        print("\n错误: 未在您的系统中找到 'go' 命令。")
        print("请先安装 Go 语言环境并确保它在您的 PATH 环境变量中。")
        return

    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp(prefix="socks5_scanner_")
        go_file_path = os.path.join(temp_dir, "scanner.go")

        with open(go_file_path, "w", encoding="utf-8") as f:
            f.write(GO_SOURCE_CODE)

        cmd = ["go", "run", go_file_path] + args_list
        
        print("\n--- 正在启动 Go 核心扫描器 ---")
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace'
        )
        for line in iter(process.stdout.readline, ''):
            print(line.strip())
        process.wait()
        print("--- 任务执行完毕 ---")

    except Exception as e:
        print(f"发生了一个意外错误: {e}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def handle_batch_scan():
    """处理批量扫描的交互逻辑"""
    print_header("批量扫描代理文件")
    proxy_file = get_validated_input(
        "请输入代理列表文件路径: ",
        validate_file_exists,
        "文件不存在，请检查路径。"
    )
    
    use_dict = input("是否使用密码本进行认证扫描? (y/n, 默认n): ").lower()
    dict_file = None
    if use_dict == 'y':
        dict_file = get_validated_input(
            "请输入密码本文件路径: ",
            validate_file_exists,
            "文件不存在，请检查路径。"
        )

    threads = get_validated_input(
        "请输入并发线程数 (默认100): ",
        lambda x: x == "" or validate_positive_integer(x),
        "请输入一个大于0的整数。"
    ) or "100"

    timeout = get_validated_input(
        "请输入连接超时时间 (秒, 默认5): ",
        lambda x: x == "" or validate_positive_integer(x),
        "请输入一个大于0的整数。"
    ) or "5"
    
    cmd_args = ["-proxyFile", proxy_file, "-threads", threads, "-timeout", timeout]
    if dict_file:
        cmd_args.extend(["-dictFile", dict_file])
    
    run_go_command(cmd_args)

def handle_single_test():
    """处理单目标测试的交互逻辑"""
    print_header("单目标快速测试")
    target = get_validated_input(
        "请输入目标 (格式 host:port): ",
        validate_target_format,
        "格式必须为 'host:port'。"
    )

    print("\n请选择认证方式:")
    print("  [1] 无认证测试")
    print("  [2] 使用单组用户名和密码测试")
    print("  [3] 使用密码本进行爆破测试")
    
    cmd_args = ["-target", target]
    while True:
        choice = input("请输入选项 [1-3]: ")
        if choice == '1':
            break
        elif choice == '2':
            creds = get_validated_input(
                "请输入凭证 (格式 user:pass): ",
                validate_creds_format,
                "格式必须为 'user:pass'。"
            )
            cmd_args.extend(["-creds", creds])
            break
        elif choice == '3':
            dict_file = get_validated_input(
                "请输入密码本文件路径: ",
                validate_file_exists,
                "文件不存在，请检查路径。"
            )
            cmd_args.extend(["-dictFile", dict_file])
            break
        else:
            print("无效选项，请输入 1, 2 或 3。")
    
    run_go_command(cmd_args)

def handle_split_file():
    """处理文件分割的交互逻辑"""
    print_header("分割代理文件")
    input_path = get_validated_input(
        "请输入要分割的源文件路径: ",
        validate_file_exists,
        "文件不存在，请检查路径。"
    )
    lines_per_file_str = get_validated_input(
        "请输入每个小文件包含的行数 (默认1000): ",
        lambda x: x == "" or validate_positive_integer(x),
        "请输入一个大于0的整数。"
    ) or "1000"
    lines_per_file = int(lines_per_file_str)

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return

    if not lines:
        print("输入文件为空，无需分割。")
        return
        
    total_lines = len(lines)
    num_files = math.ceil(total_lines / lines_per_file)
    
    print(f"\n总计 {total_lines} 行，每文件 {lines_per_file} 行，将被分割成 {num_files} 个文件。")

    file_base, file_ext = os.path.splitext(input_path)
    
    for i in range(num_files):
        output_path = f"{file_base}_part_{i+1}{file_ext}"
        start_index = i * lines_per_file
        end_index = start_index + lines_per_file
        try:
            with open(output_path, 'w', encoding='utf-8') as f_out:
                f_out.writelines(lines[start_index:end_index])
            print(f"已生成文件: {output_path}")
        except Exception as e:
            print(f"写入文件 {output_path} 时出错: {e}")
            break

def main_menu():
    """显示主菜单并处理用户选择"""
    print("\n" + "*"*60)
    print(" " * 15 + "SOCKS5 交互式工具箱 (Go 核心)")
    print(" " * 4 + "注意: 本工具仅用于学习和授权测试，请勿用于非法用途。")
    print("*"*60)
    
    while True:
        print("\n--- 主菜单 ---")
        print("  [1] 批量扫描代理文件")
        print("  [2] 单目标快速测试")
        print("  [3] 分割代理文件")
        print("  [4] 退出程序")
        
        choice = input("\n请输入您的选择 [1-4]: ")
        
        if choice == '1':
            handle_batch_scan()
        elif choice == '2':
            handle_single_test()
        elif choice == '3':
            handle_split_file()
        elif choice == '4':
            print("感谢使用，再见！")
            break
        else:
            print("无效的输入，请输入 1 到 4 之间的数字。")
        
        input("\n按 Enter 键返回主菜单...")

if __name__ == "__main__":
    main_menu()
