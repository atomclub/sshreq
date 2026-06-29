# `sshreq` & `sshgen`
原子重铸内部妙♂妙工具。

## Usage

### 请求者

1. 向拥有 SSH CA Key 的人询问得到 X25519 Public Key，例如
`gHY8cIG8VN04BRnBFineCxnjM03e77ZDtShEY85/iV0=`。

2. 本地生成一个SSH密钥。（建议定时生成新密钥）
```bash
$ ssh-keygen -t ed25519
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/chemio/.ssh/id_ed25519): /home/chemio/picasol
Enter passphrase for "/home/chemio/picasol" (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/chemio/picasol
Your public key has been saved in /home/chemio/picasol.pub
The key fingerprint is:
SHA256:z4GYG1wDMl4sT04+j8Hhxjt/LCjrCcXIsO7VSzDGwz8 chemio@alkimia
The key's randomart image is:
+--[ED25519 256]--+
|    o.o          |
|   ..+=.         |
|.   .@ .o        |
| +oo .@+ o       |
|. oBo.=*S .      |
|. ..* +o.o .     |
| ... E.+ .o      |
|. ..o.+ o o      |
| . .++   o       |
+----[SHA256]-----+
```

3. 生成CSR
```bash
$ sshreq -f [刚刚生成的**私钥**保存路径] -i [有效期] -c [第一步得到的X25519 Key]
# 例如
$ sshreq -f ~/picasol -i +1m -c gHY8cIG8VN04BRnBFineCxnjM03e77ZDtShEY85/iV0=
# 在打开的浏览器窗口中登录 Github
{"publicKey":"***************************************","interval":"+1m","auth_provider":"github","encrypted_token":"***************************","ephemeral_key":"************","signature":"********"}
```

4. 将命令输出复制并发给CA所有者

5. 所有者将输出发回请求者，请求者保存为`xxx-cert.pub`
例如
```bash
$ echo 'ssh-ed25519-cert-v01@openssh.com AAA************************************qCRwN' > ~/picasol-cert.pub
```

6. 使用密钥连接吧！
```bash
$ ssh -f ~/picasol -P 22 foo@example.com
```

### 所有者
1. 生成临时X25519密钥对(建议每次都生成临时的)

```bash
$ sshkex
X25519 Public Key:  B****************************************EU=
Private Key:  wg***************************************14=
```

2. 将公钥发送给请求者

3. 生成证书

```bash
$ sshgen -k [第一步生成的X25519 私钥] -s [SSH CA Key路径]
# 例如
$ sshgen -k QsU***************************************c= -s ~/.ssh/ca
Paste csr json here: {"publicKey":"***************************************","interval":"+1m","auth_provider":"github","encrypted_token":"***************************","ephemeral_key":"************","signature":"********"} # 粘贴请求者发送的内容
user home page: https://github.com/chemio9
user name: Clarence
 confirm? [Y/n] # 验证 Github 用户信息，如无误则输入y或直接回车
ssh-ed25519-cert-v01@openssh.com AAA*******************************************qCRwN
```

4. 所有者将输出`ssh-ed25519-cert-v01@openssh.com AAA*******************************************qCRwN`发回请求者

## 注意
部分参数只有第一次需要输入，后续操作将默认使用上一次指定的参数。

假如你曾经生成过密钥，下一次最简你只需要输入：
```bash
# X25519 密钥 使用上次的
$ sshreq -f ~/picasol -i 1m

# 曾经指定的CA Key和X25519key
$ sshgen
```
