package wecom

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h2non/filetype"

	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/channels"
	"github.com/sipeed/picoclaw/pkg/config"
	"github.com/sipeed/picoclaw/pkg/identity"
	"github.com/sipeed/picoclaw/pkg/logger"
	"github.com/sipeed/picoclaw/pkg/media"
	"github.com/sipeed/picoclaw/pkg/utils"
)

// decryptedMedia holds information about a decrypted media file
type decryptedMedia struct {
	LocalPath   string
	Data        []byte
	IsTextFile  bool
	TextContent string
	Filename    string // original filename from message or HTTP header
	ContentType string // detected MIME type
}

// downloadAndDecryptMedia downloads and decrypts a WeCom media file from an encrypted URL.
// Returns decrypted media information, or nil on error.
// filenameHint can be provided from the message's file.filename field.
func (c *WeComAIBotChannel) downloadAndDecryptMedia(ctx context.Context, encryptedURL, mediaType, filenameHint string) *decryptedMedia {
	if c.config.EncodingAESKey == "" {
		logger.WarnC("wecom_aibot", "No EncodingAESKey configured, cannot decrypt media")
		return nil
	}

	// Download encrypted data
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, encryptedURL, nil)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to create download request", map[string]any{
			"error": err.Error(),
			"url":   encryptedURL,
		})
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to download encrypted media", map[string]any{
			"error": err.Error(),
			"url":   encryptedURL,
		})
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.ErrorCF("wecom_aibot", "Media download failed", map[string]any{
			"status": resp.StatusCode,
			"url":    encryptedURL,
		})
		return nil
	}

	// Read encrypted data
	encryptedData, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to read encrypted data", map[string]any{
			"error": err.Error(),
		})
		return nil
	}

	logger.InfoCF("wecom_aibot", "Downloaded encrypted media", map[string]any{
		"size":        len(encryptedData),
		"url":         encryptedURL,
		"content-type": resp.Header.Get("Content-Type"),
	})

	// Extract filename from Content-Disposition header if available
	var filename string
	if filenameHint != "" {
		filename = filenameHint
	} else if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		// Parse Content-Disposition header for filename
		// Format: attachment; filename="file.txt" or attachment; filename*=UTF-8''file%20name.txt
		if strings.Contains(cd, "filename*=") {
			// RFC 5987 encoded filename
			parts := strings.Split(cd, "filename*=")
			if len(parts) > 1 {
				encodedName := strings.TrimSpace(parts[1])
				// Remove quotes if present
				encodedName = strings.Trim(encodedName, "\"'")
				// Extract the actual filename (after charset and language, e.g., "UTF-8''filename.txt")
				if idx := strings.Index(encodedName, "''"); idx >= 0 {
					encodedName = encodedName[idx+2:]
				}
				// URL decode
				if decoded, err := url.PathUnescape(encodedName); err == nil {
					filename = decoded
				}
			}
		} else if strings.Contains(cd, "filename=") {
			// Simple filename
			parts := strings.Split(cd, "filename=")
			if len(parts) > 1 {
				filename = strings.TrimSpace(parts[1])
				filename = strings.Trim(filename, "\"'")
			}
		}
	}

	logger.InfoCF("wecom_aibot", "Extracted filename", map[string]any{
		"filename":      filename,
		"filename_hint": filenameHint,
	})

	// Decode AES key
	aesKey, err := decodeWeComAESKey(c.config.EncodingAESKey)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to decode AES key", map[string]any{
			"error": err.Error(),
		})
		return nil
	}

	// Decrypt using AES-CBC (media files don't have the frame structure like messages)
	// For media files, we just decrypt and unpad, no frame unpacking needed
	decryptedData, err := decryptAESCBC(aesKey, encryptedData)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to decrypt media", map[string]any{
			"error": err.Error(),
			"size":  len(encryptedData),
		})
		return nil
	}

	logger.InfoCF("wecom_aibot", "Successfully decrypted media", map[string]any{
		"decrypted_size": len(decryptedData),
		"original_size":  len(encryptedData),
	})

	// Check if it's a text file
	isText, textContent := isTextFile(decryptedData)

	// Determine file extension
	ext := ".bin"
	switch mediaType {
	case "image":
		ext = ".jpg"
	case "voice":
		ext = ".amr"
	case "file":
		if isText {
			ext = ".txt"
		} else {
			ext = ".bin"
		}
	}

	// Save decrypted data to workspace media directory instead of /tmp
	// This ensures LLM can access the file via read_file tool
	mediaDir := filepath.Join(c.cfg.WorkspacePath(), "media", "wecom")
	if err := os.MkdirAll(mediaDir, 0755); err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to create media directory", map[string]any{
			"error": err.Error(),
			"path":  mediaDir,
		})
		// Fallback to temp directory if workspace is not accessible
		mediaDir = os.TempDir()
	}

	tmpFile, err := os.CreateTemp(mediaDir, "wecom-decrypted-*"+ext)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to create temp file", map[string]any{
			"error": err.Error(),
		})
		return nil
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(decryptedData); err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to write decrypted data", map[string]any{
			"error": err.Error(),
		})
		os.Remove(tmpFile.Name())
		return nil
	}

	localPath := tmpFile.Name()

	// Detect actual MIME type using magic bytes
	contentType := "application/octet-stream" // default fallback
	kind, err := filetype.MatchFile(localPath)
	if err == nil && kind != filetype.Unknown {
		contentType = kind.MIME.Value
	} else if isText {
		contentType = "text/plain"
	}

	logger.InfoCF("wecom_aibot", "Decrypted media saved", map[string]any{
		"path":         localPath,
		"size":         len(decryptedData),
		"is_text":      isText,
		"has_text":     textContent != "",
		"content_type": contentType,
	})

	return &decryptedMedia{
		LocalPath:   localPath,
		Data:        decryptedData,
		IsTextFile:  isText,
		TextContent: textContent,
		Filename:    filename,
		ContentType: contentType,
	}
}

// isTextFile checks if data looks like a text file and extracts preview if it is.
// Returns (isText bool, textContent string)
func isTextFile(data []byte) (bool, string) {
	if len(data) == 0 {
		return false, ""
	}

	// Sample first 4KB to determine if it's text
	sampleSize := len(data)
	if sampleSize > 4096 {
		sampleSize = 4096
	}

	badCount := 0
	for i := 0; i < sampleSize; i++ {
		b := data[i]
		isWhitespace := b == 0x09 || b == 0x0a || b == 0x0d // \t \n \r
		isPrintable := b >= 0x20 && b != 0x7f
		if !isWhitespace && !isPrintable {
			badCount++
		}
	}

	badRatio := float64(badCount) / float64(sampleSize)
	isText := badRatio <= 0.02

	if !isText {
		return false, ""
	}

	// Extract text content (limit to 12000 chars)
	textContent := string(data)
	if len(textContent) > 12000 {
		textContent = textContent[:12000] + "\n…(已截断)"
	}

	return true, strings.TrimSpace(textContent)
}

// WeComAIBotChannel implements the Channel interface for WeCom AI Bot (企业微信智能机器人)
type WeComAIBotChannel struct {
	*channels.BaseChannel
	config      config.WeComAIBotConfig
	cfg         *config.Config // full config for workspace access
	ctx         context.Context
	cancel      context.CancelFunc
	streamTasks map[string]*streamTask   // streamID -> task (for poll lookups)
	chatTasks   map[string][]*streamTask // chatID   -> in-flight tasks queue (FIFO)
	taskMu      sync.RWMutex
}

// streamTask represents a streaming task for AI Bot.
//
// Mutable fields (Finished, StreamClosed, StreamClosedAt) must be read/written
// while holding WeComAIBotChannel.taskMu. Immutable fields (StreamID, ChatID,
// ResponseURL, Question, CreatedTime, Deadline, answerCh, ctx, cancel) are set
// once at creation and never modified, so they are safe to read without a lock.
type streamTask struct {
	// immutable after creation
	StreamID    string
	ChatID      string // used by Send() to find this task
	ResponseURL string // temporary URL for proactive reply (valid 1 hour, use once)
	Question    string
	CreatedTime time.Time
	Deadline    time.Time          // ~30s, we close the stream here and switch to response_url
	answerCh    chan string        // receives agent reply from Send()
	ctx         context.Context    // canceled when task is removed; used to interrupt the agent goroutine
	cancel      context.CancelFunc // call on task removal to cancel ctx

	// mutable — guarded by WeComAIBotChannel.taskMu
	StreamClosed   bool      // stream returned finish:true; waiting for agent to reply via response_url
	StreamClosedAt time.Time // set when StreamClosed becomes true; used for accelerated cleanup
	Finished       bool      // fully done
	PendingMedia   []byte    // image data to send with next response_url message (base64-ready)
}

// WeComAIBotMessage represents the decrypted JSON message from WeCom AI Bot
// Ref: https://developer.work.weixin.qq.com/document/path/100719
type WeComAIBotMessage struct {
	MsgID    string `json:"msgid"`
	AIBotID  string `json:"aibotid"`
	ChatID   string `json:"chatid"`   // only for group chat
	ChatType string `json:"chattype"` // "single" or "group"
	From     struct {
		UserID string `json:"userid"`
	} `json:"from"`
	ResponseURL string `json:"response_url"` // temporary URL for proactive reply
	MsgType     string `json:"msgtype"`
	// text message
	Text *struct {
		Content string `json:"content"`
	} `json:"text,omitempty"`
	// stream polling refresh
	Stream *struct {
		ID string `json:"id"`
	} `json:"stream,omitempty"`
	// image message
	Image *struct {
		URL string `json:"url"`
	} `json:"image,omitempty"`
	// voice message
	Voice *struct {
		Content string `json:"content"` // voice recognition text
	} `json:"voice,omitempty"`
	// file message
	File *struct {
		URL      string `json:"url"`      // file download URL
		Filename string `json:"filename"` // original filename (optional)
		FileName string `json:"fileName"` // alternative field name
		Name     string `json:"name"`     // another alternative
	} `json:"file,omitempty"`
	// mixed message (text + image)
	Mixed *struct {
		MsgItem []struct {
			MsgType string `json:"msgtype"`
			Text    *struct {
				Content string `json:"content"`
			} `json:"text,omitempty"`
			Image *struct {
				URL string `json:"url"`
			} `json:"image,omitempty"`
		} `json:"msg_item"`
	} `json:"mixed,omitempty"`
	// event field
	Event *struct {
		EventType string `json:"eventtype"`
	} `json:"event,omitempty"`
}

// WeComAIBotMsgItemImage holds the image payload inside a stream message item.
type WeComAIBotMsgItemImage struct {
	Base64 string `json:"base64"`
	MD5    string `json:"md5"`
}

// WeComAIBotMsgItem is a single item inside a stream's msg_item list.
type WeComAIBotMsgItem struct {
	MsgType string                  `json:"msgtype"`
	Image   *WeComAIBotMsgItemImage `json:"image,omitempty"`
}

// WeComAIBotStreamInfo represents the detailed stream content in streaming responses.
type WeComAIBotStreamInfo struct {
	ID      string              `json:"id"`
	Finish  bool                `json:"finish"`
	Content string              `json:"content,omitempty"`
	MsgItem []WeComAIBotMsgItem `json:"msg_item,omitempty"`
}

// WeComAIBotStreamResponse represents the streaming response format
type WeComAIBotStreamResponse struct {
	MsgType string               `json:"msgtype"`
	Stream  WeComAIBotStreamInfo `json:"stream"`
}

// WeComAIBotEncryptedResponse represents the encrypted response wrapper
// Fields match WXBizJsonMsgCrypt.generate() in Python SDK
type WeComAIBotEncryptedResponse struct {
	Encrypt      string `json:"encrypt"`
	MsgSignature string `json:"msgsignature"`
	Timestamp    string `json:"timestamp"`
	Nonce        string `json:"nonce"`
}

// NewWeComAIBotChannel creates a new WeCom AI Bot channel instance
func NewWeComAIBotChannel(
	channelCfg config.WeComAIBotConfig,
	fullCfg *config.Config,
	messageBus *bus.MessageBus,
) (*WeComAIBotChannel, error) {
	if channelCfg.Token == "" || channelCfg.EncodingAESKey == "" {
		return nil, fmt.Errorf("token and encoding_aes_key are required for WeCom AI Bot")
	}

	base := channels.NewBaseChannel("wecom_aibot", channelCfg, messageBus, channelCfg.AllowFrom,
		channels.WithMaxMessageLength(2048),
		channels.WithReasoningChannelID(channelCfg.ReasoningChannelID),
	)

	return &WeComAIBotChannel{
		BaseChannel: base,
		config:      channelCfg,
		cfg:         fullCfg,
		streamTasks: make(map[string]*streamTask),
		chatTasks:   make(map[string][]*streamTask),
	}, nil
}

// Name returns the channel name
func (c *WeComAIBotChannel) Name() string {
	return "wecom_aibot"
}

// Start initializes the WeCom AI Bot channel
func (c *WeComAIBotChannel) Start(ctx context.Context) error {
	logger.InfoC("wecom_aibot", "Starting WeCom AI Bot channel...")

	c.ctx, c.cancel = context.WithCancel(ctx)

	// Start cleanup goroutine for old tasks
	go c.cleanupLoop()

	c.SetRunning(true)
	logger.InfoC("wecom_aibot", "WeCom AI Bot channel started")

	return nil
}

// Stop gracefully stops the WeCom AI Bot channel
func (c *WeComAIBotChannel) Stop(ctx context.Context) error {
	logger.InfoC("wecom_aibot", "Stopping WeCom AI Bot channel...")

	if c.cancel != nil {
		c.cancel()
	}

	c.SetRunning(false)
	logger.InfoC("wecom_aibot", "WeCom AI Bot channel stopped")
	return nil
}

// SendMedia implements the channels.MediaSender interface for WeComAIBot.
// Stores media data in the active task so it can be sent together with text via response_url.
// Since WeComAIBot response_url can only be used once, we save the image and let Send()
// send both text and image together.
func (c *WeComAIBotChannel) SendMedia(ctx context.Context, msg bus.OutboundMediaMessage) error {
	if !c.IsRunning() {
		return channels.ErrNotRunning
	}

	store := c.GetMediaStore()
	if store == nil {
		logger.WarnC("wecom_aibot", "No media store available")
		return fmt.Errorf("no media store available: %w", channels.ErrSendFailed)
	}

	// Find the active task for this chatID
	c.taskMu.Lock()
	defer c.taskMu.Unlock()

	queue := c.chatTasks[msg.ChatID]
	var task *streamTask

	// Find the first unfinished task
	for _, t := range queue {
		if !t.Finished {
			task = t
			break
		}
	}

	if task == nil {
		logger.WarnCF("wecom_aibot", "No active task for media sending", map[string]any{
			"chat_id": msg.ChatID,
		})
		return fmt.Errorf("no active task: %w", channels.ErrSendFailed)
	}

	// Process only the first media part (response_url limitation)
	if len(msg.Parts) == 0 {
		return nil
	}

	part := msg.Parts[0]

	// Resolve media reference to local file
	localPath, err := store.Resolve(part.Ref)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to resolve media ref", map[string]any{
			"ref":   part.Ref,
			"error": err.Error(),
		})
		return err
	}

	// Read file data
	imageData, err := os.ReadFile(localPath)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to read media file", map[string]any{
			"path":  localPath,
			"error": err.Error(),
		})
		return err
	}

	// Check file size (max 2MB before encoding)
	const maxImageSize = 2 * 1024 * 1024
	if len(imageData) > maxImageSize {
		logger.WarnCF("wecom_aibot", "Image too large for WeComAIBot", map[string]any{
			"size":      len(imageData),
			"max_size":  maxImageSize,
			"path":      localPath,
		})
		return fmt.Errorf("image too large (%d bytes, max %d): %w", len(imageData), maxImageSize, channels.ErrSendFailed)
	}

	// Validate image type (only JPG/PNG supported)
	kind, err := filetype.Match(imageData)
	if err != nil || (kind.MIME.Type != "image" || (kind.Extension != "jpg" && kind.Extension != "jpeg" && kind.Extension != "png")) {
		logger.WarnCF("wecom_aibot", "Unsupported media type for WeComAIBot", map[string]any{
			"mime": kind.MIME.Value,
			"ext":  kind.Extension,
			"path": localPath,
		})
		return fmt.Errorf("unsupported media type %s: %w", kind.Extension, channels.ErrSendFailed)
	}

	// Store image data in task for later sending
	task.PendingMedia = imageData

	logger.InfoCF("wecom_aibot", "Stored media for pending send", map[string]any{
		"chat_id": msg.ChatID,
		"size":    len(imageData),
		"type":    kind.Extension,
	})

	return nil
}

// Send delivers the agent reply into the active streamTask for msg.ChatID.
// It writes into the earliest unfinished task in the queue (FIFO per chatID).
// If the stream has already closed (deadline passed), it posts directly to response_url.
func (c *WeComAIBotChannel) Send(ctx context.Context, msg bus.OutboundMessage) error {
	if !c.IsRunning() {
		return channels.ErrNotRunning
	}
	c.taskMu.Lock()
	queue := c.chatTasks[msg.ChatID]
	// Only compact Finished tasks at the head of the queue.
	// Tasks that are Finished in the middle are NOT removed here: doing a full
	// scan on every Send() call would be O(n) and is unnecessary given that
	// removeTask() always splices the task out of the queue immediately.
	// Any Finished task left stranded in the middle (e.g. due to an unexpected
	// code path) will be collected by cleanupOldTasks.
	for len(queue) > 0 && queue[0].Finished {
		queue = queue[1:]
	}
	c.chatTasks[msg.ChatID] = queue
	var task *streamTask
	var streamClosed bool
	var responseURL string
	if len(queue) > 0 {
		task = queue[0]
		// Read mutable fields while holding c.taskMu to avoid data races.
		streamClosed = task.StreamClosed
		responseURL = task.ResponseURL
	}
	c.taskMu.Unlock()

	if task == nil {
		logger.DebugCF(
			"wecom_aibot",
			"Send: no active task for chat (may have timed out)",
			map[string]any{
				"chat_id": msg.ChatID,
			},
		)
		return nil
	}

	if streamClosed {
		// Stream already ended with a "please wait" notice; send the real reply via response_url.
		// Note: task.StreamID and task.ChatID are immutable, safe to read without a lock.
		logger.InfoCF("wecom_aibot", "Sending reply via response_url", map[string]any{
			"stream_id": task.StreamID,
			"chat_id":   msg.ChatID,
		})
		if responseURL != "" {
			// Check if there's pending media to send
			c.taskMu.RLock()
			hasPendingMedia := len(task.PendingMedia) > 0
			pendingMedia := task.PendingMedia
			c.taskMu.RUnlock()

			if hasPendingMedia {
				// Send image via response_url
				logger.InfoCF("wecom_aibot", "Sending pending media via response_url", map[string]any{
					"stream_id": task.StreamID,
					"size":      len(pendingMedia),
				})
				if err := c.sendImageViaResponseURL(responseURL, pendingMedia); err != nil {
					logger.ErrorCF("wecom_aibot", "Failed to send media via response_url", map[string]any{
						"error":     err,
						"stream_id": task.StreamID,
					})
					c.removeTask(task)
					return fmt.Errorf("response_url media delivery failed: %w", channels.ErrSendFailed)
				}
			} else {
				// Send text via response_url
				if err := c.sendViaResponseURL(responseURL, msg.Content); err != nil {
					logger.ErrorCF("wecom_aibot", "Failed to send via response_url", map[string]any{
						"error":     err,
						"stream_id": task.StreamID,
					})
					c.removeTask(task)
					return fmt.Errorf("response_url delivery failed: %w", channels.ErrSendFailed)
				}
			}
		} else {
			logger.WarnCF("wecom_aibot", "Stream closed but no response_url available", map[string]any{
				"stream_id": task.StreamID,
			})
		}
		c.removeTask(task)
		return nil
	}

	// Stream still open: deliver via answerCh for the next poll response.
	select {
	case task.answerCh <- msg.Content:
	case <-task.ctx.Done():
		// Task was canceled (cleanup removed it); silently drop the reply.
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// WebhookPath returns the path for registering on the shared HTTP server
func (c *WeComAIBotChannel) WebhookPath() string {
	if c.config.WebhookPath == "" {
		return "/webhook/wecom-aibot"
	}
	return c.config.WebhookPath
}

// ServeHTTP implements http.Handler for the shared HTTP server
func (c *WeComAIBotChannel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.handleWebhook(w, r)
}

// HealthPath returns the health check endpoint path
func (c *WeComAIBotChannel) HealthPath() string {
	return c.WebhookPath() + "/health"
}

// HealthHandler handles health check requests
func (c *WeComAIBotChannel) HealthHandler(w http.ResponseWriter, r *http.Request) {
	c.handleHealth(w, r)
}

// handleWebhook handles incoming webhook requests from WeCom AI Bot
func (c *WeComAIBotChannel) handleWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Log all incoming requests for debugging
	logger.DebugCF("wecom_aibot", "Received webhook request", map[string]any{
		"method": r.Method,
		"path":   r.URL.Path,
		"query":  r.URL.RawQuery,
	})

	switch r.Method {
	case http.MethodGet:
		// URL verification
		c.handleVerification(ctx, w, r)
	case http.MethodPost:
		// Message callback
		c.handleMessageCallback(ctx, w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVerification handles the URL verification request from WeCom
func (c *WeComAIBotChannel) handleVerification(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
) {
	msgSignature := r.URL.Query().Get("msg_signature")
	timestamp := r.URL.Query().Get("timestamp")
	nonce := r.URL.Query().Get("nonce")
	echostr := r.URL.Query().Get("echostr")

	logger.DebugCF("wecom_aibot", "URL verification request", map[string]any{
		"msg_signature": msgSignature,
		"timestamp":     timestamp,
		"nonce":         nonce,
	})

	// Verify signature
	if !verifySignature(c.config.Token, msgSignature, timestamp, nonce, echostr) {
		logger.ErrorC("wecom_aibot", "Signature verification failed")
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	// Decrypt echostr
	// For WeCom AI Bot (智能机器人), receiveid should be empty string
	decrypted, err := decryptMessageWithVerify(echostr, c.config.EncodingAESKey, "")
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to decrypt echostr", map[string]any{
			"error": err,
		})
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	// Remove BOM and whitespace as per WeCom documentation
	decrypted = strings.TrimPrefix(decrypted, "\ufeff")
	decrypted = strings.TrimSpace(decrypted)

	logger.InfoC("wecom_aibot", "URL verification successful")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(decrypted))
}

// handleMessageCallback handles incoming messages from WeCom AI Bot
func (c *WeComAIBotChannel) handleMessageCallback(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
) {
	msgSignature := r.URL.Query().Get("msg_signature")
	timestamp := r.URL.Query().Get("timestamp")
	nonce := r.URL.Query().Get("nonce")

	// Read request body (limit to 4 MB to prevent memory exhaustion)
	const maxBodySize = 4 << 20 // 4 MB
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to read request body", map[string]any{
			"error": err,
		})
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxBodySize {
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Parse JSON body to get encrypted message
	// Format: {"encrypt": "base64_encrypted_string"}
	var encryptedMsg struct {
		Encrypt string `json:"encrypt"`
	}
	if unmarshalErr := json.Unmarshal(body, &encryptedMsg); unmarshalErr != nil {
		logger.ErrorCF("wecom_aibot", "Failed to parse JSON body", map[string]any{
			"error": unmarshalErr,
			"body":  string(body),
		})
		http.Error(w, "Failed to parse JSON", http.StatusBadRequest)
		return
	}

	// Verify signature
	if !verifySignature(c.config.Token, msgSignature, timestamp, nonce, encryptedMsg.Encrypt) {
		logger.ErrorC("wecom_aibot", "Signature verification failed")
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	// Decrypt message
	// For WeCom AI Bot (智能机器人), receiveid is empty string
	decrypted, err := decryptMessageWithVerify(encryptedMsg.Encrypt, c.config.EncodingAESKey, "")
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to decrypt message", map[string]any{
			"error": err,
		})
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	// Parse decrypted JSON message
	var msg WeComAIBotMessage
	if unmarshalErr := json.Unmarshal([]byte(decrypted), &msg); unmarshalErr != nil {
		logger.ErrorCF("wecom_aibot", "Failed to parse decrypted JSON", map[string]any{
			"error":     unmarshalErr,
			"decrypted": decrypted,
		})
		http.Error(w, "Failed to parse message", http.StatusInternalServerError)
		return
	}

	logger.DebugCF("wecom_aibot", "Decrypted message", map[string]any{
		"msgtype": msg.MsgType,
	})

	// Process the message and get streaming response
	response := c.processMessage(ctx, msg, timestamp, nonce)

	// Check if response is empty (e.g. due to unsupported message type)
	if response == "" {
		response = c.encryptEmptyResponse(timestamp, nonce)
	}

	// Return encrypted JSON response
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(response))
}

// processMessage processes the received message and returns encrypted response
func (c *WeComAIBotChannel) processMessage(
	ctx context.Context,
	msg WeComAIBotMessage,
	timestamp, nonce string,
) string {
	logger.DebugCF("wecom_aibot", "Processing message", map[string]any{
		"msgtype": msg.MsgType,
	})

	switch msg.MsgType {
	case "text":
		return c.handleTextMessage(ctx, msg, timestamp, nonce)
	case "stream":
		return c.handleStreamMessage(ctx, msg, timestamp, nonce)
	case "image":
		return c.handleImageMessage(ctx, msg, timestamp, nonce)
	case "voice":
		return c.handleVoiceMessage(ctx, msg, timestamp, nonce)
	case "file":
		return c.handleFileMessage(ctx, msg, timestamp, nonce)
	case "mixed":
		return c.handleMixedMessage(ctx, msg, timestamp, nonce)
	case "event":
		return c.handleEventMessage(ctx, msg, timestamp, nonce)
	default:
		logger.WarnCF("wecom_aibot", "Unsupported message type", map[string]any{
			"msgtype": msg.MsgType,
		})
		return c.encryptResponse("", timestamp, nonce, WeComAIBotStreamResponse{
			MsgType: "stream",
			Stream: WeComAIBotStreamInfo{
				ID:      c.generateStreamID(),
				Finish:  true,
				Content: "Unsupported message type: " + msg.MsgType,
			},
		})
	}
}

// handleTextMessage handles text messages by starting a new streaming task
func (c *WeComAIBotChannel) handleTextMessage(
	ctx context.Context,
	msg WeComAIBotMessage,
	timestamp, nonce string,
) string {
	if msg.Text == nil {
		logger.ErrorC("wecom_aibot", "text message missing text field")
		return c.encryptEmptyResponse(timestamp, nonce)
	}

	content := msg.Text.Content
	userID := msg.From.UserID
	if userID == "" {
		userID = "unknown"
	}

	// chatID: group chat uses chatid, single chat uses userid
	chatID := msg.ChatID
	if chatID == "" {
		chatID = userID
	}

	streamID := c.generateStreamID()

	// WeCom stops sending stream-refresh callbacks after 6 minutes.
	// Set a slightly shorter deadline so we can send a timeout notice before it gives up.
	deadline := time.Now().Add(30 * time.Second)

	// Each task gets its own context derived from the channel lifetime context.
	// Canceling taskCancel interrupts the agent goroutine when the task is removed.
	taskCtx, taskCancel := context.WithCancel(c.ctx)

	task := &streamTask{
		StreamID:    streamID,
		ChatID:      chatID,
		ResponseURL: msg.ResponseURL,
		Question:    content,
		CreatedTime: time.Now(),
		Deadline:    deadline,
		Finished:    false,
		answerCh:    make(chan string, 1),
		ctx:         taskCtx,
		cancel:      taskCancel,
	}

	c.taskMu.Lock()
	c.streamTasks[streamID] = task
	c.chatTasks[chatID] = append(c.chatTasks[chatID], task)
	c.taskMu.Unlock()

	// Publish to agent asynchronously; agent will call Send() with reply.
	// Use task.ctx (not c.ctx) so the agent goroutine is canceled when the task is removed.
	go func() {
		sender := bus.SenderInfo{
			Platform:    "wecom_aibot",
			PlatformID:  userID,
			CanonicalID: identity.BuildCanonicalID("wecom_aibot", userID),
			DisplayName: userID,
		}
		peerKind := "direct"
		if msg.ChatType == "group" {
			peerKind = "group"
		}
		peer := bus.Peer{Kind: peerKind, ID: chatID}
		metadata := map[string]string{
			"channel":      "wecom_aibot",
			"chat_type":    msg.ChatType,
			"msg_type":     "text",
			"msgid":        msg.MsgID,
			"aibotid":      msg.AIBotID,
			"stream_id":    streamID,
			"response_url": msg.ResponseURL,
		}
		c.HandleMessage(task.ctx, peer, msg.MsgID, userID, chatID,
			content, nil, metadata, sender)
	}()

	// Return first streaming response immediately (finish=false, content empty)
	return c.getStreamResponse(task, timestamp, nonce)
}

// handleStreamMessage handles stream polling requests
func (c *WeComAIBotChannel) handleStreamMessage(
	ctx context.Context,
	msg WeComAIBotMessage,
	timestamp, nonce string,
) string {
	if msg.Stream == nil {
		logger.ErrorC("wecom_aibot", "Stream message missing stream field")
		return c.encryptEmptyResponse(timestamp, nonce)
	}

	streamID := msg.Stream.ID

	c.taskMu.RLock()
	task, exists := c.streamTasks[streamID]
	c.taskMu.RUnlock()

	if !exists {
		logger.DebugCF(
			"wecom_aibot",
			"Stream task not found (may be from previous session)",
			map[string]any{
				"stream_id": streamID,
			},
		)
		return c.encryptResponse(streamID, timestamp, nonce, WeComAIBotStreamResponse{
			MsgType: "stream",
			Stream: WeComAIBotStreamInfo{
				ID:      streamID,
				Finish:  true,
				Content: "Task not found or already finished. Please resend your message to start a new session.",
			},
		})
	}

	// Get next response
	return c.getStreamResponse(task, timestamp, nonce)
}

// handleImageMessage handles image messages
func (c *WeComAIBotChannel) handleImageMessage(
	ctx context.Context,
	msg WeComAIBotMessage,
	timestamp, nonce string,
) string {
	if msg.Image == nil {
		logger.ErrorC("wecom_aibot", "Image message missing image field")
		return c.encryptEmptyResponse(timestamp, nonce)
	}

	imageURL := msg.Image.URL
	userID := msg.From.UserID
	if userID == "" {
		userID = "unknown"
	}

	chatID := msg.ChatID
	if chatID == "" {
		chatID = userID
	}

	streamID := c.generateStreamID()
	deadline := time.Now().Add(30 * time.Second)
	taskCtx, taskCancel := context.WithCancel(c.ctx)

	task := &streamTask{
		StreamID:    streamID,
		ChatID:      chatID,
		ResponseURL: msg.ResponseURL,
		Question:    fmt.Sprintf("[Image: %s]", imageURL),
		CreatedTime: time.Now(),
		Deadline:    deadline,
		Finished:    false,
		answerCh:    make(chan string, 1),
		ctx:         taskCtx,
		cancel:      taskCancel,
	}

	c.taskMu.Lock()
	c.streamTasks[streamID] = task
	c.chatTasks[chatID] = append(c.chatTasks[chatID], task)
	c.taskMu.Unlock()

	// Publish to agent with image URL in content
	go func() {
		sender := bus.SenderInfo{
			Platform:    "wecom_aibot",
			PlatformID:  userID,
			CanonicalID: identity.BuildCanonicalID("wecom_aibot", userID),
			DisplayName: userID,
		}
		peerKind := "direct"
		if msg.ChatType == "group" {
			peerKind = "group"
		}
		peer := bus.Peer{Kind: peerKind, ID: chatID}

		// Log the image URL for debugging
		logger.InfoCF("wecom_aibot", "Processing image message", map[string]any{
			"image_url": imageURL,
			"msg_id":    msg.MsgID,
			"user_id":   userID,
			"chat_id":   chatID,
		})

		// Download, decrypt and store the image
		var mediaRefs []string
		store := c.GetMediaStore()
		if store != nil {
			// Use a separate context for image download with longer timeout
			// to avoid being affected by task deadline
			downloadCtx, downloadCancel := context.WithTimeout(context.Background(), 60*time.Second)
			decrypted := c.downloadAndDecryptMedia(downloadCtx, imageURL, "image", "")
			downloadCancel()

			if decrypted != nil {
				logger.InfoCF("wecom_aibot", "Image decrypted successfully", map[string]any{
					"local_path": decrypted.LocalPath,
					"image_url":  imageURL,
				})

				// Store in media store
				scope := channels.BuildMediaScope("wecom_aibot", chatID, msg.MsgID)
				ref, err := store.Store(decrypted.LocalPath, media.MediaMeta{
					Filename:    filepath.Base(decrypted.LocalPath),
					ContentType: decrypted.ContentType,
					Source:      "wecom_aibot",
				}, scope)

				if err != nil {
					logger.ErrorCF("wecom_aibot", "Failed to store image in media store", map[string]any{
						"error":      err.Error(),
						"local_path": decrypted.LocalPath,
					})
					// Clean up temp file
					os.Remove(decrypted.LocalPath)
				} else {
					logger.InfoCF("wecom_aibot", "Image stored in media store", map[string]any{
						"ref":        ref,
						"local_path": decrypted.LocalPath,
					})
					mediaRefs = append(mediaRefs, ref)
				}
			} else {
				logger.ErrorCF("wecom_aibot", "Failed to decrypt image", map[string]any{
					"image_url": imageURL,
				})
				// Don't add the URL as fallback since it's encrypted and won't work
			}
		} else {
			logger.WarnC("wecom_aibot", "No media store available")
		}

		metadata := map[string]string{
			"channel":      "wecom_aibot",
			"chat_type":    msg.ChatType,
			"msg_type":     "image",
			"msgid":        msg.MsgID,
			"aibotid":      msg.AIBotID,
			"stream_id":    streamID,
			"response_url": msg.ResponseURL,
			"image_url":    imageURL,
		}

		c.HandleMessage(task.ctx, peer, msg.MsgID, userID, chatID,
			fmt.Sprintf("Received an image: %s", imageURL), mediaRefs, metadata, sender)
	}()

	return c.getStreamResponse(task, timestamp, nonce)
}

// handleVoiceMessage handles voice messages
func (c *WeComAIBotChannel) handleVoiceMessage(
	ctx context.Context,
	msg WeComAIBotMessage,
	timestamp, nonce string,
) string {
	if msg.Voice == nil {
		logger.ErrorC("wecom_aibot", "Voice message missing voice field")
		return c.encryptEmptyResponse(timestamp, nonce)
	}

	// Voice message contains recognized text in the Content field
	content := msg.Voice.Content
	if content == "" {
		content = "[Voice message - no text recognized]"
	}

	userID := msg.From.UserID
	if userID == "" {
		userID = "unknown"
	}

	chatID := msg.ChatID
	if chatID == "" {
		chatID = userID
	}

	streamID := c.generateStreamID()
	deadline := time.Now().Add(30 * time.Second)
	taskCtx, taskCancel := context.WithCancel(c.ctx)

	task := &streamTask{
		StreamID:    streamID,
		ChatID:      chatID,
		ResponseURL: msg.ResponseURL,
		Question:    content,
		CreatedTime: time.Now(),
		Deadline:    deadline,
		Finished:    false,
		answerCh:    make(chan string, 1),
		ctx:         taskCtx,
		cancel:      taskCancel,
	}

	c.taskMu.Lock()
	c.streamTasks[streamID] = task
	c.chatTasks[chatID] = append(c.chatTasks[chatID], task)
	c.taskMu.Unlock()

	go func() {
		sender := bus.SenderInfo{
			Platform:    "wecom_aibot",
			PlatformID:  userID,
			CanonicalID: identity.BuildCanonicalID("wecom_aibot", userID),
			DisplayName: userID,
		}
		peerKind := "direct"
		if msg.ChatType == "group" {
			peerKind = "group"
		}
		peer := bus.Peer{Kind: peerKind, ID: chatID}
		metadata := map[string]string{
			"channel":      "wecom_aibot",
			"chat_type":    msg.ChatType,
			"msg_type":     "voice",
			"msgid":        msg.MsgID,
			"aibotid":      msg.AIBotID,
			"stream_id":    streamID,
			"response_url": msg.ResponseURL,
		}
		c.HandleMessage(task.ctx, peer, msg.MsgID, userID, chatID,
			content, nil, metadata, sender)
	}()

	return c.getStreamResponse(task, timestamp, nonce)
}

// handleFileMessage handles file messages
func (c *WeComAIBotChannel) handleFileMessage(
	ctx context.Context,
	msg WeComAIBotMessage,
	timestamp, nonce string,
) string {
	if msg.File == nil {
		logger.ErrorC("wecom_aibot", "File message missing file field")
		return c.encryptEmptyResponse(timestamp, nonce)
	}

	fileURL := msg.File.URL
	// Get filename from message (try different field names)
	filename := msg.File.Filename
	if filename == "" {
		filename = msg.File.FileName
	}
	if filename == "" {
		filename = msg.File.Name
	}

	userID := msg.From.UserID
	if userID == "" {
		userID = "unknown"
	}

	chatID := msg.ChatID
	if chatID == "" {
		chatID = userID
	}

	streamID := c.generateStreamID()
	deadline := time.Now().Add(30 * time.Second)
	taskCtx, taskCancel := context.WithCancel(c.ctx)

	task := &streamTask{
		StreamID:    streamID,
		ChatID:      chatID,
		ResponseURL: msg.ResponseURL,
		Question:    fmt.Sprintf("[File: %s]", fileURL),
		CreatedTime: time.Now(),
		Deadline:    deadline,
		Finished:    false,
		answerCh:    make(chan string, 1),
		ctx:         taskCtx,
		cancel:      taskCancel,
	}

	c.taskMu.Lock()
	c.streamTasks[streamID] = task
	c.chatTasks[chatID] = append(c.chatTasks[chatID], task)
	c.taskMu.Unlock()

	// Publish to agent with file URL
	go func() {
		sender := bus.SenderInfo{
			Platform:    "wecom_aibot",
			PlatformID:  userID,
			CanonicalID: identity.BuildCanonicalID("wecom_aibot", userID),
			DisplayName: userID,
		}
		peerKind := "direct"
		if msg.ChatType == "group" {
			peerKind = "group"
		}
		peer := bus.Peer{Kind: peerKind, ID: chatID}

		logger.InfoCF("wecom_aibot", "Processing file message", map[string]any{
			"file_url": fileURL,
			"filename": filename,
			"msg_id":   msg.MsgID,
			"user_id":  userID,
			"chat_id":  chatID,
		})

		// Download and decrypt the file
		var mediaRefs []string
		var finalContent string
		store := c.GetMediaStore()

		// Use a separate context for file download with longer timeout
		// to avoid being affected by task deadline (30s may not be enough for large files)
		downloadCtx, downloadCancel := context.WithTimeout(context.Background(), 60*time.Second)
		decrypted := c.downloadAndDecryptMedia(downloadCtx, fileURL, "file", filename)
		downloadCancel()

		if decrypted != nil {
			logger.InfoCF("wecom_aibot", "File decrypted successfully", map[string]any{
				"local_path": decrypted.LocalPath,
				"filename":   decrypted.Filename,
				"file_url":   fileURL,
				"is_text":    decrypted.IsTextFile,
				"size":       len(decrypted.Data),
			})

			// Use decrypted filename if available, otherwise use hint
			displayName := decrypted.Filename
			if displayName == "" {
				displayName = "未知文件"
			}

			if decrypted.IsTextFile && decrypted.TextContent != "" {
				// For text files, put content in message body instead of as attachment
				finalContent = fmt.Sprintf("Received a text file: **%s**\n\n```\n%s\n```\n\n(文件大小: %d 字节)",
					displayName, decrypted.TextContent, len(decrypted.Data))
				logger.InfoCF("wecom_aibot", "Text file content extracted", map[string]any{
					"content_length": len(decrypted.TextContent),
				})
				// Clean up temp file since we extracted the text
				os.Remove(decrypted.LocalPath)
			} else {
				// For binary files, check if it's an image (images can be sent to LLM)
				isImage := strings.HasPrefix(decrypted.ContentType, "image/")

				if store != nil {
					scope := channels.BuildMediaScope("wecom_aibot", chatID, msg.MsgID)
					ref, err := store.Store(decrypted.LocalPath, media.MediaMeta{
						Filename:    displayName,
						ContentType: decrypted.ContentType,
						Source:      "wecom_aibot",
					}, scope)

					if err != nil {
						logger.ErrorCF("wecom_aibot", "Failed to store file in media store", map[string]any{
							"error":      err.Error(),
							"local_path": decrypted.LocalPath,
						})
						os.Remove(decrypted.LocalPath)
						finalContent = fmt.Sprintf("Received a file **%s** (size: %d bytes), but failed to store it", displayName, len(decrypted.Data))
					} else {
						logger.InfoCF("wecom_aibot", "File stored", map[string]any{
							"ref":          ref,
							"filename":     displayName,
							"is_image":     isImage,
							"content_type": decrypted.ContentType,
						})

						// Add all files to mediaRefs (images will be converted to base64, others to file:// URLs)
						mediaRefs = append(mediaRefs, ref)

						if isImage {
							finalContent = fmt.Sprintf("Received an image file: **%s** (size: %d bytes)", displayName, len(decrypted.Data))
						} else {
							// Non-image files are passed as file:// URLs to LLM
							finalContent = fmt.Sprintf("Received a file: **%s** (type: %s, size: %d bytes)", displayName, decrypted.ContentType, len(decrypted.Data))
						}
					}
				} else {
					os.Remove(decrypted.LocalPath)
					finalContent = fmt.Sprintf("Received a file **%s** (size: %d bytes), but no media store available", displayName, len(decrypted.Data))
				}
			}
		} else {
			logger.ErrorCF("wecom_aibot", "Failed to decrypt file", map[string]any{
				"file_url": fileURL,
			})
			finalContent = "Received a file but failed to decrypt it"
		}

		metadata := map[string]string{
			"channel":      "wecom_aibot",
			"chat_type":    msg.ChatType,
			"msg_type":     "file",
			"msgid":        msg.MsgID,
			"aibotid":      msg.AIBotID,
			"stream_id":    streamID,
			"response_url": msg.ResponseURL,
			"file_url":     fileURL,
		}

		c.HandleMessage(task.ctx, peer, msg.MsgID, userID, chatID,
			finalContent, mediaRefs, metadata, sender)
	}()

	return c.getStreamResponse(task, timestamp, nonce)
}

// handleMixedMessage handles mixed (text + image) messages
func (c *WeComAIBotChannel) handleMixedMessage(
	ctx context.Context,
	msg WeComAIBotMessage,
	timestamp, nonce string,
) string {
	if msg.Mixed == nil || len(msg.Mixed.MsgItem) == 0 {
		logger.ErrorC("wecom_aibot", "Mixed message missing msg_item field")
		return c.encryptEmptyResponse(timestamp, nonce)
	}

	userID := msg.From.UserID
	if userID == "" {
		userID = "unknown"
	}

	chatID := msg.ChatID
	if chatID == "" {
		chatID = userID
	}

	// Build content and media refs from mixed message items
	var contentParts []string
	var mediaRefs []string
	var imageURLs []string

	// Get media store for downloading images
	store := c.GetMediaStore()

	for idx, item := range msg.Mixed.MsgItem {
		switch item.MsgType {
		case "text":
			if item.Text != nil && item.Text.Content != "" {
				contentParts = append(contentParts, item.Text.Content)
			}
		case "image":
			if item.Image != nil && item.Image.URL != "" {
				imageURL := item.Image.URL
				contentParts = append(contentParts, fmt.Sprintf("[Image: %s]", imageURL))
				imageURLs = append(imageURLs, imageURL)

				logger.InfoCF("wecom_aibot", "Processing mixed message image", map[string]any{
					"image_url": imageURL,
					"msg_id":    msg.MsgID,
					"item_idx":  idx,
				})

				// Try to download, decrypt and store the image
				if store != nil {
					// Create a context for this operation
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					decrypted := c.downloadAndDecryptMedia(ctx, imageURL, "image", "")
					cancel()

					if decrypted != nil {
						scope := channels.BuildMediaScope("wecom_aibot", chatID, msg.MsgID)
						ref, err := store.Store(decrypted.LocalPath, media.MediaMeta{
							Filename:    filepath.Base(decrypted.LocalPath),
							ContentType: decrypted.ContentType,
							Source:      "wecom_aibot",
						}, scope)

						if err == nil {
							logger.InfoCF("wecom_aibot", "Mixed message image stored", map[string]any{
								"ref": ref,
								"idx": idx,
							})
							mediaRefs = append(mediaRefs, ref)
						} else {
							logger.ErrorCF("wecom_aibot", "Failed to store mixed image", map[string]any{
								"error": err.Error(),
								"idx":   idx,
							})
							os.Remove(decrypted.LocalPath)
						}
					} else {
						logger.ErrorCF("wecom_aibot", "Failed to decrypt mixed image", map[string]any{
							"image_url": imageURL,
							"idx":       idx,
						})
					}
				}
			}
		}
	}

	content := strings.Join(contentParts, "\n")
	if content == "" {
		content = "Received mixed message with no parsable content"
	}

	streamID := c.generateStreamID()
	deadline := time.Now().Add(30 * time.Second)
	taskCtx, taskCancel := context.WithCancel(c.ctx)

	task := &streamTask{
		StreamID:    streamID,
		ChatID:      chatID,
		ResponseURL: msg.ResponseURL,
		Question:    content,
		CreatedTime: time.Now(),
		Deadline:    deadline,
		Finished:    false,
		answerCh:    make(chan string, 1),
		ctx:         taskCtx,
		cancel:      taskCancel,
	}

	c.taskMu.Lock()
	c.streamTasks[streamID] = task
	c.chatTasks[chatID] = append(c.chatTasks[chatID], task)
	c.taskMu.Unlock()

	go func() {
		sender := bus.SenderInfo{
			Platform:    "wecom_aibot",
			PlatformID:  userID,
			CanonicalID: identity.BuildCanonicalID("wecom_aibot", userID),
			DisplayName: userID,
		}
		peerKind := "direct"
		if msg.ChatType == "group" {
			peerKind = "group"
		}
		peer := bus.Peer{Kind: peerKind, ID: chatID}
		metadata := map[string]string{
			"channel":      "wecom_aibot",
			"chat_type":    msg.ChatType,
			"msg_type":     "mixed",
			"msgid":        msg.MsgID,
			"aibotid":      msg.AIBotID,
			"stream_id":    streamID,
			"response_url": msg.ResponseURL,
		}
		// Add image URLs to metadata
		if len(imageURLs) > 0 {
			metadata["image_urls"] = strings.Join(imageURLs, ",")
		}
		c.HandleMessage(task.ctx, peer, msg.MsgID, userID, chatID,
			content, mediaRefs, metadata, sender)
	}()

	return c.getStreamResponse(task, timestamp, nonce)
}

// handleEventMessage handles event messages
func (c *WeComAIBotChannel) handleEventMessage(
	ctx context.Context,
	msg WeComAIBotMessage,
	timestamp, nonce string,
) string {
	eventType := ""
	if msg.Event != nil {
		eventType = msg.Event.EventType
	}
	logger.DebugCF("wecom_aibot", "Received event", map[string]any{
		"event_type": eventType,
	})

	// Send welcome message when user opens the chat window
	if eventType == "enter_chat" && c.config.WelcomeMessage != "" {
		streamID := c.generateStreamID()
		return c.encryptResponse(streamID, timestamp, nonce, WeComAIBotStreamResponse{
			MsgType: "stream",
			Stream: WeComAIBotStreamInfo{
				ID:      streamID,
				Finish:  true,
				Content: c.config.WelcomeMessage,
			},
		})
	}

	return c.encryptEmptyResponse(timestamp, nonce)
}

// getStreamResponse gets the next streaming response for a task.
// - If agent replied: return finish=true with the real answer.
// - If deadline passed: return finish=true with a "please wait" notice, keep task alive for response_url.
// - Otherwise: return finish=false (empty), client will poll again.
func (c *WeComAIBotChannel) getStreamResponse(task *streamTask, timestamp, nonce string) string {
	var content string
	var finish bool
	var closeStreamOnly bool // close stream but do NOT remove task (response_url still pending)

	select {
	case answer := <-task.answerCh:
		// Agent replied before deadline — normal finish.
		content = answer
		finish = true
	default:
		if time.Now().After(task.Deadline) {
			// Deadline reached: close the stream with a notice, then wait for agent via response_url.
			content = "⏳ Processing, please wait. The results will be sent shortly."
			finish = true
			closeStreamOnly = true
			logger.InfoCF(
				"wecom_aibot",
				"Stream deadline reached, switching to response_url mode",
				map[string]any{
					"stream_id":    task.StreamID,
					"chat_id":      task.ChatID,
					"response_url": task.ResponseURL != "",
				},
			)
		}
		// else: still waiting, return finish=false
	}

	if finish && !closeStreamOnly {
		// Normal finish: remove from all maps.
		c.removeTask(task)
	} else if closeStreamOnly {
		// Mark stream as closed and remove from streamTasks under a single lock
		// to keep StreamClosed/StreamClosedAt consistent with map membership.
		c.taskMu.Lock()
		task.StreamClosed = true
		task.StreamClosedAt = time.Now()
		delete(c.streamTasks, task.StreamID)
		c.taskMu.Unlock()
	}

	response := WeComAIBotStreamResponse{
		MsgType: "stream",
		Stream: WeComAIBotStreamInfo{
			ID:      task.StreamID,
			Finish:  finish,
			Content: content,
		},
	}

	return c.encryptResponse(task.StreamID, timestamp, nonce, response)
}

// removeTask removes a task from both streamTasks and chatTasks, marks it finished,
// and cancels its context to interrupt the associated agent goroutine.
func (c *WeComAIBotChannel) removeTask(task *streamTask) {
	// Cancel first so the agent goroutine stops as soon as possible,
	// before we acquire the write lock.
	task.cancel()

	c.taskMu.Lock()
	task.Finished = true // written under c.taskMu, consistent with all readers
	delete(c.streamTasks, task.StreamID)
	queue := c.chatTasks[task.ChatID]
	for i, t := range queue {
		if t == task {
			c.chatTasks[task.ChatID] = append(queue[:i], queue[i+1:]...)
			break
		}
	}
	if len(c.chatTasks[task.ChatID]) == 0 {
		delete(c.chatTasks, task.ChatID)
	}
	c.taskMu.Unlock()
}

// sendViaResponseURL posts a markdown reply to the WeCom response_url.
// response_url is valid for 1 hour and can only be used once per callback.
// Returned errors are wrapped with channels.ErrRateLimit, channels.ErrTemporary,
// or channels.ErrSendFailed so the manager can apply the right retry policy.
func (c *WeComAIBotChannel) sendViaResponseURL(responseURL, content string) error {
	payload := map[string]any{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": content,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post to response_url failed: %w: %w", channels.ErrTemporary, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("response_url rate limited (%d): %s: %w",
			resp.StatusCode, respBody, channels.ErrRateLimit)
	case resp.StatusCode >= 500:
		return fmt.Errorf("response_url server error (%d): %s: %w",
			resp.StatusCode, respBody, channels.ErrTemporary)
	default:
		return fmt.Errorf("response_url returned %d: %s: %w",
			resp.StatusCode, respBody, channels.ErrSendFailed)
	}
}

// sendImageViaResponseURL posts an image message to the WeCom response_url.
// Images must be base64 encoded (max 2MB before encoding, JPG/PNG only).
// response_url is valid for 1 hour and can only be used once per callback.
func (c *WeComAIBotChannel) sendImageViaResponseURL(responseURL string, imageData []byte) error {
	// Calculate MD5 hash
	hash := fmt.Sprintf("%x", md5.Sum(imageData))

	// Encode to base64
	base64Data := base64.StdEncoding.EncodeToString(imageData)

	payload := map[string]any{
		"msgtype": "image",
		"image": map[string]string{
			"base64": base64Data,
			"md5":    hash,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal image payload: %w", err)
	}

	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, responseURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post image to response_url failed: %w: %w", channels.ErrTemporary, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("response_url rate limited (%d): %s: %w",
			resp.StatusCode, respBody, channels.ErrRateLimit)
	case resp.StatusCode >= 500:
		return fmt.Errorf("response_url server error (%d): %s: %w",
			resp.StatusCode, respBody, channels.ErrTemporary)
	default:
		return fmt.Errorf("response_url returned %d: %s: %w",
			resp.StatusCode, respBody, channels.ErrSendFailed)
	}
}

// encryptResponse encrypts a streaming response
func (c *WeComAIBotChannel) encryptResponse(
	streamID, timestamp, nonce string,
	response WeComAIBotStreamResponse,
) string {
	// Marshal response to JSON
	plaintext, err := json.Marshal(response)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to marshal response", map[string]any{
			"error": err,
		})
		return ""
	}

	logger.DebugCF("wecom_aibot", "Encrypting response", map[string]any{
		"stream_id": streamID,
		"finish":    response.Stream.Finish,
		"preview":   utils.Truncate(response.Stream.Content, 100),
	})

	// Encrypt message
	encrypted, err := c.encryptMessage(string(plaintext), "")
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to encrypt message", map[string]any{
			"error": err,
		})
		return ""
	}

	// Generate signature
	signature := computeSignature(c.config.Token, timestamp, nonce, encrypted)

	// Build encrypted response
	encryptedResp := WeComAIBotEncryptedResponse{
		Encrypt:      encrypted,
		MsgSignature: signature,
		Timestamp:    timestamp,
		Nonce:        nonce,
	}

	respJSON, err := json.Marshal(encryptedResp)
	if err != nil {
		logger.ErrorCF("wecom_aibot", "Failed to marshal encrypted response", map[string]any{
			"error": err,
		})
		return ""
	}

	logger.DebugCF("wecom_aibot", "Response encrypted", map[string]any{
		"stream_id": streamID,
	})

	return string(respJSON)
}

// encryptEmptyResponse returns a minimal valid encrypted response
func (c *WeComAIBotChannel) encryptEmptyResponse(timestamp, nonce string) string {
	// Construct a zero-value stream response and encrypt it so that
	// WeCom always receives a syntactically valid encrypted JSON object.
	emptyResp := WeComAIBotStreamResponse{}
	return c.encryptResponse("", timestamp, nonce, emptyResp)
}

// encryptMessage encrypts a plain text message for WeCom AI Bot
func (c *WeComAIBotChannel) encryptMessage(plaintext, receiveid string) (string, error) {
	aesKey, err := decodeWeComAESKey(c.config.EncodingAESKey)
	if err != nil {
		return "", err
	}

	frame, err := packWeComFrame(plaintext, receiveid)
	if err != nil {
		return "", err
	}

	// PKCS7 padding then AES-CBC encrypt
	paddedFrame := pkcs7Pad(frame, blockSize)
	ciphertext, err := encryptAESCBC(aesKey, paddedFrame)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// generateStreamID generates a random stream ID
func (c *WeComAIBotChannel) generateStreamID() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 10)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[n.Int64()]
	}
	return string(b)
}

// cleanupLoop periodically cleans up old streaming tasks
func (c *WeComAIBotChannel) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanupOldTasks()
		case <-c.ctx.Done():
			return
		}
	}
}

// cleanupOldTasks removes tasks that have exceeded their expected lifetime:
//   - Active tasks (in streamTasks): cleaned up after 1 hour (response_url validity window).
//   - StreamClosed tasks (in chatTasks only): cleaned up after streamClosedGracePeriod.
//     These tasks are waiting for the agent to call Send() via response_url. If the agent
//     crashes or times out without calling Send(), we must not let them accumulate indefinitely.
//     The grace period is generous enough to cover typical LLM latency but far shorter than 1 hour,
//     preventing chatTasks from filling up when many requests time out in quick succession.
const (
	streamClosedGracePeriod = 10 * time.Minute // max wait for agent after stream closes
	taskMaxLifetime         = 1 * time.Hour    // absolute max (≈ response_url validity)
)

func (c *WeComAIBotChannel) cleanupOldTasks() {
	c.taskMu.Lock()
	defer c.taskMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-taskMaxLifetime)
	for id, task := range c.streamTasks {
		if task.CreatedTime.Before(cutoff) {
			delete(c.streamTasks, id)
			task.cancel() // interrupt agent goroutine still waiting for LLM
			queue := c.chatTasks[task.ChatID]
			for i, t := range queue {
				if t == task {
					c.chatTasks[task.ChatID] = append(queue[:i], queue[i+1:]...)
					break
				}
			}
			if len(c.chatTasks[task.ChatID]) == 0 {
				delete(c.chatTasks, task.ChatID)
			}
			logger.DebugCF("wecom_aibot", "Cleaned up expired task", map[string]any{
				"stream_id": id,
			})
		}
	}
	// Clean up StreamClosed tasks from chatTasks.
	// Two expiry conditions are checked:
	//  1. Absolute expiry: task was created more than taskMaxLifetime ago.
	//  2. Grace expiry: stream closed more than streamClosedGracePeriod ago
	//     (agent had enough time to reply; it is not coming back).
	for chatID, queue := range c.chatTasks {
		filtered := queue[:0]
		for i, t := range queue {
			absoluteExpired := t.CreatedTime.Before(cutoff)
			graceExpired := t.StreamClosed &&
				!t.StreamClosedAt.IsZero() &&
				t.StreamClosedAt.Before(now.Add(-streamClosedGracePeriod))
			if t.Finished {
				// Finished tasks should have been removed by removeTask().
				// Finding one here (especially not at position 0) means an
				// unexpected code path left it stranded, causing the queue to
				// grow silently. Log a warning so it is visible, then drop it.
				if i > 0 {
					logger.WarnCF("wecom_aibot",
						"Found stranded Finished task in the middle of chatTasks queue; "+
							"this should not happen — removeTask() should have spliced it out",
						map[string]any{
							"chat_id":   chatID,
							"stream_id": t.StreamID,
							"position":  i,
						})
				}
				// The task is already finished; its context was already canceled
				// by removeTask(), so no further action is required.
				continue
			} else if !absoluteExpired && !graceExpired {
				filtered = append(filtered, t)
			} else {
				t.cancel() // cancel any lingering agent goroutine
			}
		}
		if len(filtered) == 0 {
			delete(c.chatTasks, chatID)
		} else {
			c.chatTasks[chatID] = filtered
		}
	}
}

// handleHealth handles health check requests
func (c *WeComAIBotChannel) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	if !c.IsRunning() {
		status = "not running"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": status,
	})
}
