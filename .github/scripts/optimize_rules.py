import re

def load_rules(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('!')]

def remove_duplicate_headers(filename):
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        header_lines = []
        rule_lines = []
        is_header = True
        for line in lines:
            if line.startswith('!'):
                header_lines.append(line)
            else:
                is_header = False
                rule_lines.append(line)

        # Deduplicate header lines while preserving order
        unique_header_lines = []
        seen = set()
        for line in header_lines:
            if line not in seen:
                unique_header_lines.append(line)
                seen.add(line)

        with open(filename, 'w', encoding='utf-8') as f:
            f.writelines(unique_header_lines)
            f.writelines(rule_lines)

    except FileNotFoundError:
        print(f"File not found: {filename}")
    except Exception as e:
        print(f"An error occurred: {e}")

def check_inclusion(rule1, rule2):
  # 简单包含检测，你可以根据实际情况调整更复杂的匹配方式
    if rule1 in rule2:
       return True
    else:
        return False

def optimize_rules(input_filename, output_filename):
    rules = load_rules(input_filename)
    optimized_rules = []
    rules_to_remove = set()

    for i, rule1 in enumerate(rules):
        if i in rules_to_remove:  # 如果此规则已经被标记为要删除，跳过
            continue
        
        for j, rule2 in enumerate(rules):
            if i == j or j in rules_to_remove: # 避免和自身比较或已经标记删除的比较
                continue

            if check_inclusion(rule1, rule2):
                rules_to_remove.add(j) # 标记 rule2 需要删除

    for i, rule in enumerate(rules):
        if i not in rules_to_remove:
            optimized_rules.append(rule)

    # 写入优化后的规则, 并保留文件头
    remove_duplicate_headers(input_filename)

    with open(output_filename, 'w', encoding='utf-8') as f:
        #写入文件头
        with open(input_filename,'r',encoding='utf-8') as file:
            header_lines = []
            for line in file:
                if line.startswith('!'):
                    header_lines.append(line)
            f.writelines(header_lines)

        for rule in optimized_rules:
            f.write(rule + '\n')

if __name__ == "__main__":
    optimize_rules("ziyongdnsZ1", "ziyongdns")
    optimize_rules("ziyongrulerZ1", "ziyongruler")