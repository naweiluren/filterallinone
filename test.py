import re
import dns.resolver
import pandas as pd
from datetime import datetime, timedelta
import os

# --- 配置 ---
ADGUARD_RULE_FILE = 'adguard_rules.txt'  # 你的AdGuard规则文件路径
RECORD_FILE = 'domain_detection_records.csv' # 检测记录文件路径
PUBLIC_DNS_SERVERS = ['1.1.1.1', '8.8.8.8'] # 用于检测的公共DNS服务器

def check_domain_availability(domain):
    """
    通过DNS查询检测域名是否可用。
    如果能解析到A或AAAA记录，则认为可用。
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = PUBLIC_DNS_SERVERS
    # resolver.timeout = 2  # 设置查询超时时间
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
    
def is_dns_rule(rule):
    """
    检查规则是否为只包含域名的 DNS 过滤规则。

    Args:
        rule: 要检查的规则字符串。

    Returns:
        如果规则是有效的 DNS 规则，则返回 True，否则返回 False。
    """
    if "/" in rule or "." not in rule:
        return False
    
    # 处理 AdBlock Plus 选项部分（$后面的内容）
    if '$' in rule:
        # 分割规则和选项
        rule_part, options_part = rule.split('$', 1)
        rule = rule_part
        
        # 可选：验证选项部分格式（如需要）
        # 选项部分通常由 | 分隔的多个域名组成，如 denyallow=a.com|b.com
        # 这里不做严格验证，只确保主规则部分是域名
    else:
        options_part = ""

    if "." not in rule:
        return False    

    print(f'start _ {rule}')
    
    # 更严格的域名匹配模式，包括对端口号的可选匹配
    rule = rule.replace('@', '').replace('|', '').replace('^', '').replace('$', '')

    print(rule)
    pattern = r'^([a-zA-Z0-9*][a-zA-Z0-9*-]*\.)*[a-zA-Z0-9*][a-zA-Z0-9*-]*(\.a-zA-Z)?$'
    result = bool(re.match(pattern, rule))
    print(f'end _ {rule}')
    return result    

def split_domain_rules(rule):
    """
    专门处理 $3p,xhr,domain=subhd.tv|subhdtw.com|zzzzz688.com 格式的规则
    """
    if 'domain=' not in rule:
        return [rule]
    
    # 分离前缀和domain部分
    parts = rule.split('domain=', 1)
    prefix = parts[0] + 'domain='
    
    # 获取domain部分，并处理可能的后续选项
    domain_and_suffix = parts[1]
    
    # 检查是否有其他选项（逗号分隔）
    if ',' in domain_and_suffix:
        domain_part, suffix = domain_and_suffix.split(',', 1)
        suffix = ',' + suffix
    else:
        domain_part = domain_and_suffix
        suffix = ''
    
    # 拆分多个域名
    domains = domain_part.split('|')
    
    # 生成新规则
    result = []
    for domain in domains:
        new_rule = prefix + domain + suffix
        result.append(new_rule)
    
    return result    

def process_denyallow_rule(rule):
    """
    处理单条 denyallow 规则
    逻辑：
    1. 严格检查：只允许 $denyallow=，不允许其他修饰符
    2. 安全校验：denyallow 后面的域名必须是主域名的子域
    """
    try:
        # --- 严格修饰符检查 ---
        if re.search(r'\$(?!denyallow=)', rule):
            return [] # 直接丢弃整条规则

        if '$denyallow=' not in rule:
            return []
            
        parts = rule.split('$denyallow=', 1)
        main_part = parts[0].strip()
        exception_part = parts[1].strip()

        # --- 提取主规则域名 ---
        main_domain = None
        if main_part.startswith('||') and main_part.endswith('^'):
            main_domain = main_part[2:-1]

        rules = []
        # 1. 保留主规则
        rules.append(main_part)

        # --- 处理例外列表 ---
        exception_parts = re.split(r'[|,^]+', exception_part)
        
        for part in exception_parts:
            domain = part.strip()
            if not domain:
                continue

            if main_part.startswith('@@'):
                # 原放行 -> 例外拦截 (生成黑名单/拦截规则)
                rules.append(f"||{domain}^")
            else:
                # 原拦截 -> 例外放行 (生成白名单/放行规则)
                rules.append(f"@@||{domain}^")
        
        return rules
        
    except Exception as e:
        # 捕获异常但不中断，返回空列表跳过该规则
        return []    

if __name__ == "__main__":
    
    # print(is_dns_rule('||0.beer^'))
    # print(is_dns_rule('||druggedrat.com^$all'))
    
    # print(is_dns_rule('||ad-host-backup-*.aliyuncs.com^'))

    print(is_dns_rule('||*$script,third-party,denyallow=tvableon.me|mega.co.nz|mega.nz|libs.baidu.com|ilfcdn.li|bytecdntp.com|doodcdn.io|intensedebate.com|vixcloud.co|rsc.cdn77.org|linkvertise.com|fastly.net|statically.io|sharecast.ws|b-cdn.net|bunnycdn.ru|bootstrapcdn.com|cdn.ampproject.org|cloudflare.com|cdn.staticfile.org|disqus.com|disquscdn.com|dmca.com|ebacdn.com|facebook.net|fastlylb.net|fbcdn.net|fluidplayer.com|fontawesome.com|github.io|google.com|googleapis.com|googletagmanager.com|gstatic.com|jquery.com|jsdelivr.net|jwpcdn.com|jwplatform.com|jwplayer.com|recaptcha.net|shrink.pe|twitter.com|ulogin.ru|unpkg.com|userapi.com|vidazoo.com|vk.com|yastatic.net|ytimg.com|zencdn.net|youtube.com|cackle.me|googleoptimize.com|vuukle.com|chatango.com|twimg.com|google-analytics.com|hcaptcha.com|media-imdb.com|blogger.com|hwcdn.net|instagram.com|wp.com|fastcomments.com|plyr.io|imgsmail.ru|cloudflare.net|rabbitstream.net|x.com|ko-fi.com|wsimg.com|sharethis.com|utteranc.es|cloudflareinsights.com|tailwindcss.com|capo6play.com|jpg5.su|jpg6.su|tolstoycomments.com|code.iconify.design|alicdn.com|addtoany.com|waust.at,_____,domain=fapfappy.com|onestream.xyz|123movieshd.*|sportsonline.*|ducumon.click|sextb.date|sextb.net|sports-stream.*|igg-games.com|pcgamestorrents.com|igg-games.co|watchcriminalminds.com|up-4.net|upload-4ever.com|123movie.*|seegames.xyz|musicriders.blogspot.com|streameast.watch|watchserieshd.live|alivegore.com|bestporncomix.com|rawkuma.com|rule34hentai.net|123-movies.zone|up-4ever.net|rivofutboltv.club|tuktukcinema.*|ssrmovies.singles|kissasian.*|animeunity.cc|zeriun.cc|cineb.app|1377x.to|furher.in|himovies.sx|hexupload.net|justfullporn.net|mega4upload.com|kissanimefree.cc|yugenanime.tv|witanime.cyou|fireload.com|mixdroop.*|hentaiasmr.moe|daddylivehd.*|meetdownload.com|file-upload.org|sotwe.com|1337xx.to|opensubtitles.org|bunkrr.su|bunkr.*|bunkr.ci|bunkr.ph|bunkr.pk|bunkr.media|bunkr.red|bunkr.ax|oxy.st|backfirstwo.com|5.45.95.74|3dporndude.com|thepiratebay.zone|mmsbee24.com|faselhd.*|manga-lek.net|wecima.cloud|goone.pro|deepgoretube.site|megaup.net|1tamilblasters.*|185.217.95.44|peeplink.in|ebookhunter.net|mdbekjwqa.pw|limetorrents.lol|akuma.moe|imgdawgknuttz.com|pahe.me|rawinu.com|nicomanga.com|mdfx9dc8n.net|toonily.me|nxbrew.net|faselhd-embed.scdns.io|mdzsmutpcvykb.net|bestgirlsexy.com|hdhub4u.mov|bluemediadownload.*|mixdropjmk.pw|drivemoe.com|moviekhhd.biz|free-content.pro|newmangaraw.com|mixdrop21.net|kaas.*|kickassanime.*|kickassanimes.*|everia.club|faselhdtv.*|animeunity.to|get-to.link|eztvx.to|urlbluemedia.*|arcasiangrocer.store|novelfull.com|jav.land|tvappapk.com|gogoanimes.fi|nativesurge.info|mercenaryenrollments.net|readcomiconline.li|tututweak.app|y2mate.is|braflix.ru|javgg.co|javgg.net|mangadistrict.com|poscitechs.xyz|bentomanga.top|bigcomics.bid|brmangas.top|cmoa1.top|janime.top|jpraw.xyz|kakuyomu.in|kkraw.com|komiku.win|lectormanga.top|lermanga.top|manga1000.top|manga1001.win|manga1001.xyz|mangajp.top|mangakl.su|mangaraw.bid|mangavy.com|mangaz.win|scanita.top|shinigami-id.top|sushiscan.top|javplayer.org|lodynet.link|play.playkrx18.site|projectjav.com|pandamtl.com|cyberfile.me|full4movies.network|cosmic1.co|kuyhaa.me|gamingweb.xyz|tmohentai.com|iegybest.club|kuyhaa-me.site|gaycock4u.com|infinityscans.net|infinityscans.xyz|streamtape.*|mangaraw.ac|file-zz40pd56-embed.com|tempatwisata.pro|bunkr-albums.io|fap-nation.org|egyrbyeteuh.sbs|egydead.center|9xplayer.com|javsek.net|thepiratebay3.co|prmovies.im|krakenfiles.com|noxx.to|mixdrop.ps|mixdrop.is|daddylivehd1.click|manhwatoon.com|bitcine.app|fmovies-hd.to|cliphotnews.*|eromanga-show.com|hentai-one.com|hentaipaw.com|mp4upload.com|livecamrips.tv|pervtube.net|xtremestream.xyz|tpi.li|jestful.net|flaswish.com|fsdcmo.sbs|strimsy.top|kaliscan.io|japteenx.com|videzz.net|hivecomic.com|yts-official.mx|animeworld.*|itdmusics.com|lmanime.com|zavalise.com|bluedownload.*|likemanga.ink|y2meta.net|jgvdata.com|realpornblogger.com|natomanga.com|soap2day.day|jpg5.su|rule34.*|bollyzone.to|vidfast.pro|cricstreams.re|kissjav.com|flickystream.net|tempodeconhecer.blogs.sapo.pt|pelisxporno.net|tvsportslive.fr|turbovid.me|erokomiksi.com|daftporn.com|cin.guru|cineb.rs|shahid4u.*|fastream.to|fullboys.com|game3rb.com|builddiamond.net|capoplay.net|canna-power.to|canna.to|kaliscan.me|anizone.to|foodtechnos.in|mangaplus.shueisha.tv|shueisharaw.tv|spotidownloader.com|luluvdoo.com|pornslash.com|md3b0j6hj.com|javcode.net|filmnudes.com|jpg6.su|gamesmain.xyz|shahid-4u.*|likemanga.*|animesrbija.com|simpcity.*|simpcity.cr|simpcity.is|kimochi.info|asmr18.fans|doujinantena.top|mens1069.com|pahe.plus|fbol.top|advertape.net|saint2.cr|saint2.su|hdmovie99.cv|arigl.com|x-fetish.tube|niyaniya.moe|cyberdrop.cr|katfile.online|ajdown.space|flixmomo.com|mixdrop23.net|lek-manga.net|sshahid4u.*|severeporn.com|hentaianimezone.com|mapple.uk|watch.spencerdevs.xyz|hentaivox.com|vidnest.io|totalsportek.*|totalsportek.army|comick.art|turbovid.cr|klmanga.ec|archived.moe|thebarchive.com|game-repack.site|primewire.mov|romsdroid.com|khoindvn.io.vn|modfyp.com|streamix.so|nudesboys.com|hepidrive.online|hentaicop.com|pandamovies.org|embedseek.online|rpmplay.online|hexload.com|pornwatch.ws|vidara.to|xtapes.porn|sxyland.com|bmovies.vip|search.extto.com|daemon-hentai.com|mangarawjp.tv|imagepond.net|truyenqqno.com|1377x.is|1337x.tw|gupload.xyz|vidnest.live|share.boodstream.cc|rule34vault.com|manhuarmtl.com|erothots.is|erothots.co|erothots1.com|leakgallery.com|simply-hentai.com|r-34.xyz|erosxsun.xyz|tm-earn.com|twkan.com|tpead.net^'))

    # print(is_dns_rule('||druggedrat.com^$denyallow=a.druggedrat.com|b.druggedrat.com'))

    # print(process_denyallow_rule('||druggedrat.com^$denyallow=a.druggedrat.com|b.druggedrat.com'))

    # rule = '$object,script,subdocument,3p,websocket,xhr,domain=xbiqige.cc|niuyankan.top|ixdzs.tw|xpshuku.com|iqmxs.cc|xddxsw.net|haobetter.com|hutuxs.com|lakyworld.com|biquge543.com|biquge12345.com|biquge.ac|biquge321.com|zyywenxue.com|biquge77.net|xiakezw.com|shitouxs.com|yzbg.net|alexij.net|hshfm.com|biqugequ.org|biqiuge5.org|fxxs3.com|hushuge.com|49gtk.cc|tongrenshe.cc|tbxs.org|efuxs.com|i3book.com|13xsw.com|genbiquge.com|xiaoshuo.com.tw|quanbiqu.com|20me.net|622zw.com|jvbiquge.com|yebiquge.com|huananxs.top|fbqg.cc|taobiquge.com|xianguke.net|timaxs.com|piaotianxiaoshuo.com|tellgillian.com|82zg.com|erciyan.com|kbook8.com|87nb.com|0sxs.com|m-ia.net|cleavagecoverup.com|vipbiquge.com|68read.cc|83kss.cc|memduh.net|jpbqg7.com|ehuxs.com|qishupu.com|fmh18.net|biquge85.com|bqduo.cc|panguxs.org|131453.xyz|haitang30.com|ykxs.cc|ltxswu.me|vjungle.com|dbrxs.org|11bqg.com|xbotaodz.com|56xiaoshuo.net|kunnu.com|yushuwu.cloud|yourbiquge.com|biquge345.com|666biquge.com|qs1669.net|wxsck.com|biqutime.com|00ksw.com|0794.org|123dua.com|123wx.cc|126shu.org|12zw.net|13txt.net|147xiaoshuo.com|156zw.com|17k.com|1biqu.com|2kans.net|1pwx.com|1qxs.com|23hh.com|23qb.com|23qb.net|23sk.net|23us.tw|23wxx.com|23xstxt.net|24kxs.cc|2kxs.info|333uu.org|360xs.com|38kanshu.net|3yt.com|477zw.com|4xiaoshuo.net|50zw.co|50zw.com|50zww.net|51eshu.com|52bqg.org|52shuku123.org|52xs.net|56shuku.info|59xs.com|6666xsw.com|67shu.net|69kshu.win|69zww.com|7017k.net|777zw.net|779buy.com|77xsw.cc|8181zw.vip|81book.com|91zww.com|93xscc.com|99mk.net|9tiefu.com|a6ksw.net|abqg5200.com|aiwx.info|aixiashu.net|aixs.la|aikushuge.com|b520.cc|b5200.net|bbiquge.cc|bbiquge8.net|bequmo.com|bimixsw.com|biqivge.cc|biqudd.com|biqudu.tv|biquge365.net|biquge5200.net|biquge775.com|biquge98.net|xbiquge99.cc|biqugecd.com|biqugen.net|biqugeks.org|biqugewu.net|aidu123.com|biquluo.info|biqusk.com|biqutsxs.com|bisowu.cc|bisowu.net|55561.net|bokanx.com|booktxts.com|boquku.com|bqq999.cc|bqwxg8.com|bshuku.com|bxwx.live|bxwx00.com|changduzw.com|chenkuan.com|china-wuling.com|damengzhu1.com|ddbqgtxt.cc|diyibanzhu.buzz|diyibanzhu9.pro|dizishu.cc|dobiez.com|doupocangqiong.info|dpcq1.com|dpcq1.net|feibzw.com|fkxs.net|fxsc6.net|gaofuwu.org|gdbzkz.info|guanshuya.com|haitangmi.xyz|hongyeshuzhai.com|ibiquges.com|ibiquges.org|ibotaodz.org|idzs.org|ijjjxs.net|imianhuatang.info|ishisetianxia.com|ishubao.org|itshang.com|xvipxs.net|iwurexs.info|ixs.la|jcdf99.com|jieshengit.com|jiezhong.cc|jingwubook.com|jmshuwu.net|kanshushi.com|lewen123.com|lewenge.cc|lewxs.com|liewenn.com|liudatxt.org|longzu5.net|luoqiu.io|lzbao.net|maxreader.la|mcmssc.net|mingrenteahouse.com|msxsw.com|nuanyuehanxing.com|paoshu8.com|paoshuzw.com|piaotian.la|piaotian55.com|pksge.com|prpcoin.com|qiqidu.net|qishula.com|qishuta.info|qqxsw.so|quge66.com|ranwen.la|rizhaoxs.com|roushuwu6.com|sdhear.com|shanhaimiwenlu.com|shenshuxs.org|shu008.com|shubaowang.cc|shumi.la|shumil.co|shuquso.com|shuyy8.com|silukex.com|siluwx.org|sinodan.cc|sjks88.com|soduha.la|sthuojia.org|stxsw.com|sytxt.cc|tianzhangs.com|tpsge.info|trxs.cc|tutengzw.com|txtduo.com|txtwan.com|tysk.cc|u33.cc|u33.me|wenxuem.com|wenxuemi.cc|whzh-xs.com|woaidu.info|wodexiaoshuoh.com|wolaidu1.com|x23us.us|xbiqugela.com|xbiquke.com|xdingdian.cc|xhytd.com|xiashuyun.com|xiaxs.info|xinremenxs.com|xiushukong.com|xqianqian.cc|xs5200.com|xs7788.com|xsb-xs.com|xstt5.com|xszww8.net|xuanjiezhimen.org|xuanshu.org|xuessex.com|xxbiqudu.com|xygwh.cc|xyuanzunxs.com|ygshu.com|yingsx.com|gytmh.com|ymxwx.com|yqd6.com|ysxs8.vip|yunxs.info|yuyougu.com|zhuishubox.com|zydu3.com|zzs5.info'
    # rule = '$image,3p,domain=lady1.top'
    # print(split_domain_rules(rule))
    # rule = '$image,3p'
    # print(split_domain_rules(rule))

    