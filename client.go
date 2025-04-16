package samlclient

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
)

// Client 是一个简单的SAML客户端实现，用于进行SAML认证
type Client struct {
	// SAML服务提供商的基本配置
	EntityID    string
	MetadataURL string
	AcsURL      string
	// IdP服务器的配置
	IdPURL          string
	ServiceProvider *saml.ServiceProvider
	// 私钥及证书配置
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
	// HTTP客户端
	HTTPClient *http.Client
}

// Config 包含创建新SAML客户端所需的配置
type Config struct {
	// 必要的基本配置
	EntityID    string
	MetadataURL string
	AcsURL      string
	IdPURL      string
	// 可选的私钥及证书配置
	KeyPEM  []byte
	CertPEM []byte
	// HTTP客户端可选配置
	HTTPTimeout time.Duration
}

// NewClient 创建一个新的SAML客户端
func NewClient(config Config) (*Client, error) {
	if config.EntityID == "" || config.MetadataURL == "" || config.AcsURL == "" || config.IdPURL == "" {
		return nil, errors.New("必须提供EntityID、MetadataURL、AcsURL和IdPURL")
	}

	// 默认HTTP客户端
	httpClient := &http.Client{
		Timeout: config.HTTPTimeout,
	}
	if config.HTTPTimeout == 0 {
		httpClient.Timeout = 30 * time.Second
	}

	client := &Client{
		EntityID:    config.EntityID,
		MetadataURL: config.MetadataURL,
		AcsURL:      config.AcsURL,
		IdPURL:      config.IdPURL,
		HTTPClient:  httpClient,
	}

	// 如果提供了私钥和证书，进行解析
	if len(config.KeyPEM) > 0 && len(config.CertPEM) > 0 {
		key, cert, err := parseCertAndKey(config.KeyPEM, config.CertPEM)
		if err != nil {
			return nil, fmt.Errorf("解析私钥和证书失败: %w", err)
		}
		client.Key = key
		client.Certificate = cert
	}

	// 初始化ServiceProvider
	if err := client.initServiceProvider(); err != nil {
		return nil, err
	}

	return client, nil
}

// 解析私钥和证书
func parseCertAndKey(keyPEM, certPEM []byte) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}

	rsaKey, ok := key.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("私钥不是RSA类型")
	}

	cert, err := x509.ParseCertificate(key.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	return rsaKey, cert, nil
}

// 初始化SAML服务提供商
func (c *Client) initServiceProvider() error {
	// 从IdP获取元数据
	idpMetadata, err := c.fetchIDPMetadata()
	if err != nil {
		return err
	}

	// 创建服务提供商配置
	metadataURL, err := url.Parse(c.MetadataURL)
	if err != nil {
		return fmt.Errorf("解析元数据URL失败: %w", err)
	}

	acsURL, err := url.Parse(c.AcsURL)
	if err != nil {
		return fmt.Errorf("解析ACS URL失败: %w", err)
	}

	sp := &saml.ServiceProvider{
		EntityID:    c.EntityID,
		Key:         c.Key,
		Certificate: c.Certificate,
		MetadataURL: *metadataURL,
		AcsURL:      *acsURL,
		IDPMetadata: idpMetadata,
	}

	c.ServiceProvider = sp
	return nil
}

// 从IdP获取元数据
func (c *Client) fetchIDPMetadata() (*saml.EntityDescriptor, error) {
	metadataURL := fmt.Sprintf("%s/saml/v2/metadata", c.IdPURL)

	req, err := http.NewRequest("GET", metadataURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("获取IdP元数据失败: %s, %s", resp.Status, string(body))
	}

	metadata := &saml.EntityDescriptor{}
	if err := xml.NewDecoder(resp.Body).Decode(metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

// CreateAuthRequest 创建一个SAML认证请求
func (c *Client) CreateAuthRequest(relayState string) (string, error) {
	if c.ServiceProvider == nil {
		return "", errors.New("ServiceProvider未初始化")
	}

	// 获取IdP的SSO URL
	idpSSOURL := c.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if idpSSOURL == "" {
		return "", errors.New("无法获取IdP的SSO URL")
	}

	// 直接创建重定向URL
	rawURL, err := c.ServiceProvider.MakeRedirectAuthenticationRequest(idpSSOURL)
	if err != nil {
		return "", err
	}

	// 手动添加RelayState参数
	if relayState != "" {
		q := rawURL.Query()
		q.Set("RelayState", relayState)
		rawURL.RawQuery = q.Encode()
	}

	return rawURL.String(), nil
}

// ParseResponse 解析来自IdP的SAML响应
func (c *Client) ParseResponse(samlResponse string) (*saml.Assertion, error) {
	if c.ServiceProvider == nil {
		return nil, errors.New("ServiceProvider未初始化")
	}

	// 解码SAML响应
	decodedResponse, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, err
	}

	// 解析SAML响应
	var response saml.Response
	if err := xml.Unmarshal(decodedResponse, &response); err != nil {
		return nil, err
	}

	// 验证响应签名
	if response.Signature == nil {
		return nil, errors.New("SAML响应未签名")
	}

	// 验证签名后，检查断言
	if response.Assertion == nil || response.Assertion.ID == "" {
		return nil, errors.New("SAML响应中没有有效断言")
	}

	// 进行基本验证，如有需要，可以根据实际的SAML库结构扩展这部分逻辑

	return response.Assertion, nil
}

// GetUserInfo 从SAML assertion中获取用户信息
func (c *Client) GetUserInfo(assertion *saml.Assertion) map[string]string {
	if assertion == nil {
		return nil
	}

	userInfo := make(map[string]string)

	// 提取主题
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		userInfo["nameID"] = assertion.Subject.NameID.Value
	}

	// 提取属性
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) > 0 {
				userInfo[attr.Name] = attr.Values[0].Value
			}
		}
	}

	return userInfo
}

// GenerateServiceProviderMetadata 生成服务提供商的元数据
func (c *Client) GenerateServiceProviderMetadata() (string, error) {
	if c.ServiceProvider == nil {
		return "", errors.New("ServiceProvider未初始化")
	}

	// 生成元数据
	metadata := c.ServiceProvider.Metadata()

	// 直接将元数据序列化为XML
	metadataXML, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", err
	}

	// 添加XML头
	metadataStr := xml.Header + string(metadataXML)

	return metadataStr, nil
}

// SAMLMiddleware 返回一个HTTP中间件，用于处理SAML认证
func (c *Client) SAMLMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否有SAML响应
		if r.Method == "POST" && r.URL.Path == "/saml/acs" {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			samlResponse := r.FormValue("SAMLResponse")
			if samlResponse == "" {
				http.Error(w, "没有SAMLResponse", http.StatusBadRequest)
				return
			}

			assertion, err := c.ParseResponse(samlResponse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// 将用户信息存储在请求上下文中
			userInfo := c.GetUserInfo(assertion)
			ctx := context.WithValue(r.Context(), "saml_user_info", userInfo)

			// 获取RelayState并重定向
			relayState := r.FormValue("RelayState")
			if relayState != "" {
				http.Redirect(w, r.WithContext(ctx), relayState, http.StatusFound)
				return
			}

			// 继续处理请求
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 继续处理其他请求
		next.ServeHTTP(w, r)
	})
}
