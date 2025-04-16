package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"samlclient"
)

func main() {
	// 读取SSL证书和密钥（可选）
	certPath := filepath.Join("config", "cert.pem")
	keyPath := filepath.Join("config", "key.pem")

	var certPEM, keyPEM []byte
	var err error

	// 如果文件存在，则读取证书和密钥
	if _, err := os.Stat(certPath); err == nil {
		certPEM, err = os.ReadFile(certPath)
		if err != nil {
			log.Fatalf("无法读取证书: %v", err)
		}
	}

	if _, err := os.Stat(keyPath); err == nil {
		keyPEM, err = os.ReadFile(keyPath)
		if err != nil {
			log.Fatalf("无法读取密钥: %v", err)
		}
	}

	// 创建SAML客户端配置
	config := samlclient.Config{
		// 替换为你的实际配置
		EntityID:    "https://your-service.example.com/saml",
		MetadataURL: "https://your-service.example.com/saml/metadata",
		AcsURL:      "https://your-service.example.com/saml/acs",
		// 如果使用Zitadel，需要提供完整的Zitadel URL或其他SAML IdP的URL
		IdPURL:  "https://your-zitadel-instance.example.com",
		KeyPEM:  keyPEM,
		CertPEM: certPEM,
	}

	// 创建SAML客户端
	client, err := samlclient.NewClient(config)
	if err != nil {
		log.Fatalf("创建SAML客户端失败: %v", err)
	}

	// 生成并打印SP元数据（用于配置IdP）
	spMetadata, err := client.GenerateServiceProviderMetadata()
	if err != nil {
		log.Fatalf("生成SP元数据失败: %v", err)
	}
	fmt.Printf("服务提供商元数据:\n%s\n", spMetadata)

	// 设置处理器
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// 创建认证请求，并设置RelayState（重定向URL）
		authURL, err := client.CreateAuthRequest("https://your-service.example.com/profile")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	// 使用SAML中间件处理ACS端点
	http.Handle("/saml/acs", client.SAMLMiddleware(http.HandlerFunc(acsHandler)))
	http.HandleFunc("/profile", profileHandler)

	// 添加一个元数据端点，用于IdP配置
	http.HandleFunc("/saml/metadata", func(w http.ResponseWriter, r *http.Request) {
		metadata, err := client.GenerateServiceProviderMetadata()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(metadata))
	})

	// 启动HTTP服务器
	fmt.Println("服务器启动在 :8080 端口...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// 首页处理器
func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html>
		<head>
			<title>SAML客户端示例</title>
		</head>
		<body>
			<h1>SAML客户端示例</h1>
			<p>点击下面的按钮进行SAML认证</p>
			<a href="/login">登录</a>
		</body>
		</html>
	`)
}

// ACS处理器（SAML响应的断言消费服务）
func acsHandler(w http.ResponseWriter, r *http.Request) {
	// 用户信息已经由中间件添加到上下文中
	userInfo, ok := r.Context().Value("saml_user_info").(map[string]string)
	if !ok {
		http.Error(w, "没有找到用户信息", http.StatusInternalServerError)
		return
	}

	// 输出用户信息（仅用于演示）
	log.Printf("认证成功，用户信息: %v", userInfo)

	// 将用户重定向到个人资料页面
	http.Redirect(w, r, "/profile", http.StatusFound)
}

// 个人资料页面处理器
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// 在生产环境中，你应该从会话或其他存储中获取用户信息
	// 这只是一个示例
	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html>
		<head>
			<title>用户资料</title>
		</head>
		<body>
			<h1>用户资料</h1>
			<p>认证成功！</p>
			<p>这里应该显示用户信息，在实际应用中，这些信息会从会话中获取。</p>
		</body>
		</html>
	`)
}
