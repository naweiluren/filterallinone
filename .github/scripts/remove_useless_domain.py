import re
import dns.resolver
import pandas as pd
from datetime import datetime, timedelta
import concurrent.futures # 导入 concurrent.futures 模块
import os

# --- 配置 ---
ADGUARD_RULE_FILE = 'adguard_rules.txt'  # 你的AdGuard规则文件路径
NEW_ADGUARD_RULE_FILE = 'adguard_rules_cleaned.txt' # 生成的清理后的规则文件
RECORD_FILE = 'domain_detection_records.csv' # 检测记录文件路径
PUBLIC_DNS_SERVERS = ['1.1.1.1', '8.8.8.8'] # 用于检测的公共DNS服务器

# --- 时间阈值（以天为单位）---
AVAILABLE_SKIP_THRESHOLD_DAYS = 180  # 半年 = 180天
UNAVAILABLE_CHECK_THRESHOLD_DAYS = 7 # 7天

# --- 辅助函数 ---

def extract_domains_from_adguard_rules_and_map_lines(file_path):
    """
    从 AdGuard 兼容的规则文件中提取纯域名，并保留原始行内容及行号。
    这样我们可以在后续匹配到具体要删除的行。
    返回:
        all_lines: 原始文件所有行列表
        domain_to_line_map: 域名 -> 原始行内容 (包含规则格式) 的字典
        extracted_domains: 纯域名列表
    """
    all_lines = []
    domain_to_line_map = {} # 存储 {纯域名: 原始规则行}
    extracted_domains = set()

    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f):
            all_lines.append(line) # 保留原始行，但不包含换行符
            stripped_line = line.strip()

            if not stripped_line or stripped_line.startswith('!') or stripped_line.startswith('#'):
                continue

            # AdGuard/Adblock Plus 规则: ||domain.com^ ||*.domain.com^
            match = re.search(r'\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)?', stripped_line)
            if match:
                domain = match.group(1).lstrip('*')
                if domain.startswith('.'): domain = domain[1:]
                # domains.add(domain)
                domain_to_line_map[domain] = stripped_line
                extracted_domains.add(domain)
                continue

            # Hosts 格式: 0.0.0.0 domain.com
            match = re.search(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', stripped_line)
            if match:
                domain = match.group(2)
                domain_to_line_map[domain] = stripped_line
                extracted_domains.add(domain)
                continue
            
            # 纯域名格式: domain.com (直接一行一个域名)
            if re.fullmatch(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', stripped_line):
                domain = stripped_line
                domain_to_line_map[domain] = stripped_line
                extracted_domains.add(domain)

    return all_lines, domain_to_line_map, sorted(list(extracted_domains))

def check_domain_availability(domain):
    """
    通过DNS查询检测域名是否可用。
    如果能解析到A或AAAA记录，则认为可用。
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = PUBLIC_DNS_SERVERS
    resolver.timeout = 5  # 设置查询超时时间
    # resolver.lifetime = 2 # 设置整个查询过程的超时时间

    try:
        # 尝试查询 A 记录
        resolver.query(domain, 'A')
        return True
    except dns.resolver.NXDOMAIN:
        # 域名不存在
        return False
    except dns.resolver.NoAnswer:
        return False
    except (dns.resolver.Timeout):
        # 查询超时
        print(f"  Warning: DNS query timed out for {domain}, retrying...")
        try: # 尝试第二次
            resolver.query(domain, 'A')
            return True
        except Exception as e:
            return False
    except Exception as e:
        # 其他错误
        # print(f"  Error checking {domain}: {e}")
        return False

# --- 主逻辑 ---

def load_records(record_file):
    """加载历史检测记录"""
    if os.path.exists(record_file):
        df = pd.read_csv(record_file)
        # 确保 '检测时间' 列是 datetime 对象
        df['检测时间'] = pd.to_datetime(df['检测时间'])
        return df
    return pd.DataFrame(columns=['域名', '检测时间', '检测次数', '检测结果'])

def save_records(df, record_file):
    """保存检测记录"""
    df.to_csv(record_file, index=False)


# --- 新的函数：用于线程池执行的包装器 ---
def process_domain_entry(domain, records_df, current_time):
    """
    处理单个域名的逻辑，以便在线程池中运行。
    返回一个字典，包含该域名的最新处理结果。
    """
    historical_record = records_df[records_df['域名'] == domain].copy() 

    last_check_time = None
    last_result = None
    check_count = 0

    if not historical_record.empty:
        last_check_time = historical_record['检测时间'].iloc[0]
        last_result = historical_record['检测结果'].iloc[0]
        check_count = historical_record['检测次数'].iloc[0]

    domain_available = None

    # 逻辑 1: 可用且半年内
    if last_result == '可用' and last_check_time and \
       (current_time - last_check_time).days <= AVAILABLE_SKIP_THRESHOLD_DAYS:
        
        return {
            '域名': domain,
            '检测时间': last_check_time,
            '检测次数': check_count,
            '检测结果': '可用'
        } 

    # 逻辑 2: 如果域名检测为不可用时，且检测时间为7天内则直接返回不可用
    # 如果超过7天，且检测次数大于等于4次，也返回不可用
    elif last_result == '不可用' and last_check_time and \
            ((current_time - last_check_time).days <= UNAVAILABLE_CHECK_THRESHOLD_DAYS or \
            (check_count >= 4 and (current_time - last_check_time).days <= AVAILABLE_SKIP_THRESHOLD_DAYS)):
        
        # print(f"  Skipping check for '{domain}': Previously unavailable within {UNAVAILABLE_CHECK_THRESHOLD_DAYS} days.")
        return {
            '域名': domain,
            '检测时间': last_check_time,
            '检测次数': check_count,
            '检测结果': '不可用'
        }

    # 如果需要实际检测
    domain_available = check_domain_availability(domain)
    
    if not domain_available: 
        if last_result != '不可用':
            check_count = 1 
        else: 
            check_count += 1
    else: 
        check_count = 0 
    
    return {
        '域名': domain,
        '检测时间': current_time,
        '检测次数': check_count,
        '检测结果': '可用' if domain_available else '不可用'
    }    

def main():
    print(f"--- Domain Availability Checker ---")

    # 1. 加载历史记录
    records_df = load_records(RECORD_FILE)
    print(f"Loaded {len(records_df)} historical records.")

    # 2. 读取AdGuard规则文件并提取域名
    print(f"Extracting domains from {ADGUARD_RULE_FILE}...")
    original_adguard_lines, domain_to_rule_map, domains_to_check = \
        extract_domains_from_adguard_rules_and_map_lines(ADGUARD_RULE_FILE)
    print(f"Extracted {len(domains_to_check)} unique domains.")

    current_time = datetime.now()
    updated_records = []
    # 存储需要从规则文件中删除的域名（纯域名形式）
    domains_to_delete_from_rules = set() 


    with concurrent.futures.ThreadPoolExecutor(max_workers=500) as executor:
        # 提交所有域名任务
        # executor.map() 按照提交的顺序返回结果，但执行是并行的
        futures = {executor.submit(process_domain_entry, domain, records_df, current_time): domain 
                   for domain in domains_to_check}
        
        # 实时打印进度和收集结果
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            updated_records.append({
                '域名': result['域名'],
                '检测时间': result['检测时间'],
                '检测次数': result['检测次数'],
                '检测结果': result['检测结果']
            })
            if result['检测结果'] == '不可用':
                domains_to_delete_from_rules.add(result['域名'])
            
            # 打印进度，例如每处理100个域名打印一次
            if (i + 1) % 100 == 0 or (i + 1) == len(domains_to_check):
                print(f"  Processed {i + 1}/{len(domains_to_check)} domains...")

    print("All parallel DNS checks finished.")

    # 3. 更新并保存记录
    # 将新的检测结果合并到旧的记录中

    if updated_records:
        new_df = pd.DataFrame(updated_records)
        
        # 将新记录按域名合并到旧记录中，如果域名存在则更新，不存在则添加
        # 使用 concat 和 drop_duplicates 来实现覆盖更新
        combined_df = pd.concat([records_df[~records_df['域名'].isin(new_df['域名'])], new_df])
        
        save_records(combined_df, RECORD_FILE)
        print(f"\nDetection complete. Records saved to {RECORD_FILE}")
        print(f"Total domains in record file: {len(combined_df)}")

    # 4. 根据检测结果，生成新的 AdGuard 规则文件 (直接删除不写入任何东西)
    print(f"\nGenerating new AdGuard rules file: {NEW_ADGUARD_RULE_FILE}...")
    
    deleted_count = 0
    with open(NEW_ADGUARD_RULE_FILE, 'w', encoding='utf-8') as outfile:
        for original_line_with_newline in original_adguard_lines:
            stripped_line = original_line_with_newline.strip()
            
            # 默认保留非规则行（注释、空行）
            is_rule_line = False
            associated_domain = None

            # 尝试通过正则表达式反向匹配出该规则行对应的“纯域名”
            match_abp = re.search(r'\|\|([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\^|\$)?', stripped_line)
            match_hosts = re.search(r'^(0\.0\.0\.0|127\.0\.0\.1|::1)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', stripped_line)
            match_pure = re.fullmatch(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', stripped_line)

            if match_abp:
                associated_domain = match_abp.group(1).lstrip('*')
                if associated_domain.startswith('.'): associated_domain = associated_domain[1:]
                is_rule_line = True
            elif match_hosts:
                associated_domain = match_hosts.group(2)
                is_rule_line = True
            elif match_pure:
                associated_domain = match_pure.group(0)
                is_rule_line = True

            # 如果是规则行，检查其对应的域名是否在待删除列表中
            if is_rule_line and associated_domain in domains_to_delete_from_rules:
                # 标记为删除，不写入文件
                deleted_count += 1
            else:
                # 保留此行（非规则行或不是待删除的规则）
                outfile.write(original_line_with_newline)
                
    print(f"Deleted {deleted_count} rules/domains from the new rules file (no trace left).")
    print(f"New rules file saved to {NEW_ADGUARD_RULE_FILE}")


import sys
if __name__ == "__main__":
    
    try:
        print("输入文件为:", sys.argv[1])
        ADGUARD_RULE_FILE = sys.argv[1]
        print("输出文件为:", sys.argv[2])
        NEW_ADGUARD_RULE_FILE = sys.argv[2]
    except Exception as e:
        print("Input Error:", e)
    main()