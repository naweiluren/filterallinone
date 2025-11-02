
# filterallinone

```
    更新时间: 2025-11-03 07:26:08 （北京时间） 

ziyongdns: 132649 lines
ziyongruler: 38398 lines
```

一个github能用的脚本或者工作流,用于合并Adguard的过滤规则,思路如下:合并自定义的Adguard官方规则,并将其存储在AdguardDNSRuler和Adguardruler,合并列表自定义第三方规则,并将其合并在ziyongdnsZ和ziyongrulerZ,如果AdguardDNSRuler和ziyongdnsZ中有相同规则,则删除ziyongdnsZ中的相同规则,并将规则存储到ziyongdnsZ1中,同理处理Adguardruler和ziyongrulerZ的规则,井存储到ziyongrulerZ1,最后对ziyongdnsZ1和ziyongrulerZ1进行优化,查看ziyongdnsZ1的规则中是否有包含关系的规则,如果有,则删除被包含的规则,并存储到ziyongdns中,同理处理ziyongrulerZ1,然后处理后存储到ziyongruler
dns增减检测机制, 有效域名每180天检测一次，无效域名每7天检测一次持续4次无效者180天再次检测
    