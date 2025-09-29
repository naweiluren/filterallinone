import re
import dns.resolver
import pandas as pd
from datetime import datetime, timedelta
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
        # 域名存在但没有A记录（可能只有MX或NS记录），仍然认为是可解析的
        # 这里为了简化，我们认为没有A记录就不算“可用”，可以根据实际需求调整
        try:
             resolver.query(domain, 'AAAA') # 尝试查询AAAA记录
             return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.LifetimeTimeout):
             return False
    except (dns.resolver.Timeout):
        # 查询超时
        print(f"  Warning: DNS query timed out for {domain}, retrying...")
        try: # 尝试第二次
            resolver.query(domain, 'A')
            return True
        except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
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

    for domain in domains_to_check:
        print(f"Processing domain: {domain}")
        # 从历史记录中找到当前域名
        # .copy() 是为了避免 SettingWithCopyWarning
        historical_record = records_df[records_df['域名'] == domain].copy() 

        last_check_time = None
        last_result = None
        check_count = 0

        if not historical_record.empty:
            last_check_time = historical_record['检测时间'].iloc[0]
            last_result = historical_record['检测结果'].iloc[0]
            check_count = historical_record['检测次数'].iloc[0]
            print(f"  Found historical record: Last check at {last_check_time}, Result: {last_result}, Count: {check_count}")

        domain_available = None # 初始化为 None
        perform_actual_check = True # 是否需要进行实际的DNS查询

        # 逻辑 1: 如果域名检测结果为可用，且检测时间为半年内则不用检测直接通过。
        if last_result == '可用' and last_check_time and \
           (current_time - last_check_time).days <= AVAILABLE_SKIP_THRESHOLD_DAYS:
            
            domain_available = True # 标记为可用
            perform_actual_check = False # 不需要实际检测
            print(f"  Skipping check for '{domain}': Previously available within {AVAILABLE_SKIP_THRESHOLD_DAYS} days.")

        # 逻辑 2: 如果域名检测为不可用时，且检测时间为7天内则直接返回不可用
        elif last_result == '不可用' and last_check_time and \
             ((current_time - last_check_time).days <= UNAVAILABLE_CHECK_THRESHOLD_DAYS or \
             (check_count >= 4 and (current_time - last_check_time).days <= AVAILABLE_SKIP_THRESHOLD_DAYS)):
            
            domain_available = False # 标记为不可用
            perform_actual_check = False # 不需要实际检测
            domains_to_delete_from_rules.add(domain)
            print(f"  Skipping check for '{domain}': Previously unavailable within {UNAVAILABLE_CHECK_THRESHOLD_DAYS} days.")
            # 此时不需要增加检测次数，因为没有真正检测

        # 如果需要实际检测
        if perform_actual_check:
            print(f"  Performing actual DNS check for {domain}...")
            domain_available = check_domain_availability(domain)
            check_count += 1
            print(f"  Actual Check Result: {'可用' if domain_available else '不可用'}")
            
            # 如果实际检测后是不可用，且之前也是不可用，则重置检测次数
            # “如果仍然不通则检测次数加1” 这个逻辑只在“旧记录不可用且超过7天，然后去检测，发现仍然不可用”时触发。
            # 如果是第一次检测，或者以前是可用现在发现不可用，直接设为1。
            if not domain_available:
                if last_result != '不可用' or not last_check_time or \
                   (current_time - last_check_time).days > UNAVAILABLE_CHECK_THRESHOLD_DAYS:
                    check_count = 1 # 重新开始计数不可用次数
                else: # 之前不可用，在7天外检测，现在仍然不可用
                    check_count += 1
            else: # 如果现在检测发现是可用，则这次检测是可用的，清零连续不可用次数
                check_count = 0 
                
            updated_records.append({
                '域名': domain,
                '检测时间': current_time,
                '检测次数': check_count,
                '检测结果': '可用' if domain_available else '不可用'
            })

            # --- 新增删除逻辑判断 ---
            if not domain_available:
                print(f"  Domain '{domain}' is marked for deletion (unavailable {check_count} times).")
                domains_to_delete_from_rules.add(domain)

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