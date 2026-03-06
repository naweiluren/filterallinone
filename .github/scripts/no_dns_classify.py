# -*- coding: utf-8 -*-
import re
import argparse
import os
from collections import defaultdict

# ==========================================
# 配置区
# ==========================================
BUFFER_SIZE = 1000

# ==========================================
# 特征词库
# ==========================================
ANDROID_MODS = {'app', 'popup', 'replace', 'headers', 'empty', 'mp4', 'xml'}
IOS_MODS = {'csp', 'json-prune'}

PATTERN_ANDROID_WORD = re.compile(r'\b(android|apk|droid|intent:|market:)\b', re.I)
PATTERN_IOS_WORD = re.compile(r'\b(ios|iphone|ipad|macos|itms-|itmss)\b', re.I)

def classify_rule(rule):
    line = rule.strip()
    if not line or line.startswith('!') or len(line) < 3:
        return None

    dollar_pos = line.find('$')
    has_modifiers = (dollar_pos != -1)
    modifiers_part = line[dollar_pos:].lower() if has_modifiers else ''

    # 平台专属修饰符检测
    if has_modifiers:
        if any(f'${mod}' in modifiers_part or f',{mod}' in modifiers_part for mod in ANDROID_MODS):
            return 'android'
        if any(f'${mod}' in modifiers_part or f',{mod}' in modifiers_part for mod in IOS_MODS):
            return 'ios'

    # 关键词检测
    has_android = bool(PATTERN_ANDROID_WORD.search(line))
    has_ios = bool(PATTERN_IOS_WORD.search(line))

    if has_android and not has_ios:
        return 'android'
    elif has_ios and not has_android:
        return 'ios'

    # 默认归类：通用规则
    return 'common'

def main():
    parser = argparse.ArgumentParser(description='规则分类分流器')
    parser.add_argument('--input', '-i', required=True, help='输入文件')
    parser.add_argument('--out-android', required=True, help='Android 输出')
    parser.add_argument('--out-ios', required=True, help='iOS 输出')
    parser.add_argument('--out-common', required=True, help='通用输出')
    args = parser.parse_args()

    # 清理旧文件
    for out_file in [args.out_android, args.out_ios, args.out_common]:
        if os.path.exists(out_file):
            os.remove(out_file)

    buffers = {'android': [], 'ios': [], 'common': []}
    stats = defaultdict(int)

    try:
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                category = classify_rule(line)
                if category:
                    buffers[category].append(line)
                    stats[category] += 1

                    if len(buffers[category]) >= BUFFER_SIZE:
                        with open(vars(args)[f'out_{category}'], 'a', encoding='utf-8') as f_out:
                            f_out.writelines(buffers[category])
                        buffers[category].clear()

        # 写入剩余
        for cat, buf in buffers.items():
            if buf:
                with open(vars(args)[f'out_{cat}'], 'a', encoding='utf-8') as f_out:
                    f_out.writelines(buf)

        print(f"✅ 分类完成！统计: {dict(stats)}")

    except Exception as e:
        print(f"❌ 分类失败: {e}")
        exit(1)

if __name__ == "__main__":
    main()