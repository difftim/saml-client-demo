// Package main contains an example service provider implementation.
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml/samlsp"
)

var samlMiddleware *samlsp.Middleware

func hello(w http.ResponseWriter, r *http.Request) {
	// 记录会话中的属性
	log.Println("用户成功认证，会话属性:")

	// 记录所有可用的属性 - 使用IdP元数据中定义的属性名称
	ctx := r.Context()
	log.Printf("  NameID: %s", samlsp.AttributeFromContext(ctx, "name_id"))
	log.Printf("  SessionIndex: %s", samlsp.AttributeFromContext(ctx, "session_index"))
	log.Printf("  Email: %s", samlsp.AttributeFromContext(ctx, "Email"))
	log.Printf("  SurName: %s", samlsp.AttributeFromContext(ctx, "SurName"))
	log.Printf("  FirstName: %s", samlsp.AttributeFromContext(ctx, "FirstName"))
	log.Printf("  FullName: %s", samlsp.AttributeFromContext(ctx, "FullName"))
	log.Printf("  UserName: %s", samlsp.AttributeFromContext(ctx, "UserName"))
	log.Printf("  UserID: %s", samlsp.AttributeFromContext(ctx, "UserID"))

	// 尝试从会话中获取所有属性
	if session := samlsp.SessionFromContext(ctx); session != nil {
		log.Println("会话信息:")
		log.Printf("  会话类型: %T", session)

		// 检查是否是SessionWithAttributes类型
		if sessionWithAttrs, ok := session.(samlsp.SessionWithAttributes); ok {
			log.Println("会话中的属性:")
			attrs := sessionWithAttrs.GetAttributes()
			for name, values := range attrs {
				log.Printf("  %s: %v", name, values)
			}
		} else {
			log.Println("警告: 会话不支持属性接口")
		}
	} else {
		log.Println("警告: 无法从上下文中获取会话")
	}

	// 尝试获取用户显示名称，优先使用FullName，如果没有则使用UserName
	displayName := samlsp.AttributeFromContext(r.Context(), "FullName")
	if displayName == "" {
		displayName = samlsp.AttributeFromContext(r.Context(), "UserName")
	}
	if displayName == "" {
		displayName = "未知用户"
	}

	log.Printf("用户访问 hello 页面: %s", displayName)
	fmt.Fprintf(w, "Hello,  %s!", displayName)
}

func logout(w http.ResponseWriter, r *http.Request) {
	nameID := samlsp.AttributeFromContext(r.Context(), "name_id")
	url, err := samlMiddleware.ServiceProvider.MakeRedirectLogoutRequest(nameID, "")
	if err != nil {
		log.Printf("创建登出请求错误: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = samlMiddleware.Session.DeleteSession(w, r)
	if err != nil {
		log.Printf("删除会话错误: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Add("Location", url.String())
	w.WriteHeader(http.StatusFound)
	log.Printf("用户登出成功，重定向到: %s", url.String())
}

func main() {
	// 配置日志输出到文件
	logFile, err := os.OpenFile("saml_debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("无法打开日志文件: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.Println("SAML服务启动...")

	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		log.Fatalf("加载证书错误: %v", err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Fatalf("解析证书错误: %v", err)
	}

	// 从本地文件加载IdP元数据
	log.Printf("正在从本地文件加载IdP元数据")
	metadataBytes, err := os.ReadFile("local-saml-metadata.xml")
	if err != nil {
		log.Fatalf("读取IdP元数据文件错误: %v", err)
	}

	idpMetadata, err := samlsp.ParseMetadata(metadataBytes)
	if err != nil {
		log.Fatalf("解析IdP元数据错误: %v", err)
	}

	log.Printf("成功加载IdP元数据")

	//
	rootURL, err := url.Parse("https://srv.bdb.im/sso/")
	if err != nil {
		log.Fatalf("解析根URL错误: %v", err)
	}

	// 记录配置的URL
	log.Printf("配置的根URL: %s", rootURL.String())
	log.Printf("预期的元数据URL: %s", rootURL.ResolveReference(&url.URL{Path: "saml/metadata"}).String())

	samlMiddleware, _ = samlsp.New(samlsp.Options{
		EntityID:    "samltest",
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true, // some IdP require the SLO request to be signed
	})

	// 记录详细的SAML配置信息
	log.Printf("SAML配置详情:")
	log.Printf("  EntityID: %s", samlMiddleware.ServiceProvider.EntityID)
	log.Printf("  ACS URL: %s", samlMiddleware.ServiceProvider.AcsURL)
	log.Printf("  Metadata URL: %s", samlMiddleware.ServiceProvider.MetadataURL)
	log.Printf("  SLO URL: %s", samlMiddleware.ServiceProvider.SloURL)

	// 打印ServiceProvider的完整配置
	log.Printf("ServiceProvider配置:")
	log.Printf("  EntityID: %s", samlMiddleware.ServiceProvider.EntityID)
	log.Printf("  MetadataURL: %s", samlMiddleware.ServiceProvider.MetadataURL)
	log.Printf("  AcsURL: %s", samlMiddleware.ServiceProvider.AcsURL)
	log.Printf("  SloURL: %s", samlMiddleware.ServiceProvider.SloURL)

	app := http.HandlerFunc(hello)
	slo := http.HandlerFunc(logout)

	// 创建请求记录器中间件
	requestLogger := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("收到请求: %s %s", r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	}

	// 注册路由
	http.Handle("/sso/hello", requestLogger(samlMiddleware.RequireAccount(app)))
	http.Handle("/sso/logout", requestLogger(slo))

	// 注册SAML相关的路由，处理包含/sso前缀的请求
	http.Handle("/sso/saml/metadata", requestLogger(samlMiddleware))
	http.Handle("/sso/saml/acs", requestLogger(samlMiddleware))
	http.Handle("/sso/saml/slo", requestLogger(samlMiddleware))

	// 添加一个测试路由，用于验证服务器是否正常运行
	http.HandleFunc("/sso/test", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("测试路由被访问")
		fmt.Fprintf(w, "服务器正常运行")
	})

	server := &http.Server{
		Addr:              ":7777",
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
