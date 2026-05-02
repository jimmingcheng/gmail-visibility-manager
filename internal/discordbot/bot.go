package discordbot

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/config"
	"github.com/jimmingcheng/gmail-visibility-manager/internal/manager"
)

// Bot is the optional Discord approval adapter. It is not the policy boundary;
// it only submits decisions to Manager.
type Bot struct {
	cfg     config.DiscordConfig
	manager *manager.Manager
	session *discordgo.Session
	allowed map[string]bool
}

// New returns nil when Discord config is incomplete or the token env is unset.
func New(cfg config.DiscordConfig, mgr *manager.Manager) (*Bot, error) {
	if strings.TrimSpace(cfg.ChannelID) == "" || len(cfg.AllowedUserIDs) == 0 {
		return nil, nil
	}
	token := strings.TrimSpace(os.Getenv(cfg.TokenEnv))
	if token == "" {
		return nil, nil
	}
	session, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, fmt.Errorf("create discord session: %w", err)
	}
	allowed := make(map[string]bool, len(cfg.AllowedUserIDs))
	for _, id := range cfg.AllowedUserIDs {
		if id = strings.TrimSpace(id); id != "" {
			allowed[id] = true
		}
	}
	bot := &Bot{
		cfg:     cfg,
		manager: mgr,
		session: session,
		allowed: allowed,
	}
	session.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsDirectMessages | discordgo.IntentsMessageContent
	session.AddHandler(bot.onMessage)
	return bot, nil
}

// Start opens the Discord gateway session.
func (b *Bot) Start() error {
	if b == nil {
		return nil
	}
	if err := b.session.Open(); err != nil {
		return fmt.Errorf("open discord session: %w", err)
	}
	return nil
}

// Close closes the Discord gateway session.
func (b *Bot) Close() error {
	if b == nil {
		return nil
	}
	return b.session.Close()
}

// NotifyPending sends a concise approval prompt to Discord.
func (b *Bot) NotifyPending(ctx context.Context, requestID string) error {
	if b == nil {
		return nil
	}
	record, err := b.manager.Store().GetRequest(ctx, requestID)
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("Pending Gmail visibility request `%s`\nSender: `%s`\nLabels: `%s`\nRationale: %s\nUse `%s approve %s` or `%s deny %s <reason>`.",
		record.RequestID,
		record.Email,
		strings.Join(record.ClassificationLabels, ", "),
		escapeLine(record.Rationale),
		b.cfg.CommandPrefix,
		record.RequestID,
		b.cfg.CommandPrefix,
		record.RequestID)
	_, err = b.session.ChannelMessageSend(b.cfg.ChannelID, msg)
	return err
}

func (b *Bot) onMessage(_ *discordgo.Session, msg *discordgo.MessageCreate) {
	if msg == nil || msg.Author == nil || msg.Author.Bot {
		return
	}
	if msg.ChannelID != b.cfg.ChannelID {
		return
	}
	if !b.allowed[msg.Author.ID] {
		return
	}
	content := strings.TrimSpace(msg.Content)
	prefix := strings.TrimSpace(b.cfg.CommandPrefix)
	if prefix == "" {
		prefix = "!gvm"
	}
	if !strings.HasPrefix(content, prefix) {
		return
	}
	args := strings.Fields(strings.TrimSpace(strings.TrimPrefix(content, prefix)))
	if len(args) == 0 {
		b.reply(msg.ChannelID, "commands: pending, show <request-id>, approve <request-id>, deny <request-id> [reason]")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	switch args[0] {
	case "pending":
		records, err := b.manager.Store().ListPending(ctx)
		if err != nil {
			b.reply(msg.ChannelID, "error: "+err.Error())
			return
		}
		if len(records) == 0 {
			b.reply(msg.ChannelID, "No pending Gmail visibility requests.")
			return
		}
		lines := make([]string, 0, len(records))
		for _, record := range records {
			lines = append(lines, fmt.Sprintf("`%s` `%s` labels=`%s`", record.RequestID, record.Email, strings.Join(record.ClassificationLabels, ",")))
		}
		b.reply(msg.ChannelID, strings.Join(lines, "\n"))
	case "show":
		if len(args) != 2 {
			b.reply(msg.ChannelID, "usage: "+prefix+" show <request-id>")
			return
		}
		record, err := b.manager.Store().GetRequest(ctx, args[1])
		if err != nil {
			b.reply(msg.ChannelID, "error: "+err.Error())
			return
		}
		b.reply(msg.ChannelID, fmt.Sprintf("`%s` status=`%s`\nSender: `%s`\nLabels: `%s`\nRationale: %s",
			record.RequestID, record.Status, record.Email, strings.Join(record.ClassificationLabels, ", "), escapeLine(record.Rationale)))
	case "approve":
		if len(args) != 2 {
			b.reply(msg.ChannelID, "usage: "+prefix+" approve <request-id>")
			return
		}
		_, grant, reconcile, err := b.manager.Approve(ctx, args[1], "discord:"+msg.Author.ID)
		if err != nil {
			b.reply(msg.ChannelID, "error: "+err.Error())
			return
		}
		extra := ""
		if reconcile != nil {
			extra = "\nGmail: `" + reconcile.Status + "`"
		}
		b.reply(msg.ChannelID, fmt.Sprintf("Approved `%s` for `%s` with labels `%s`.%s", args[1], grant.Email, strings.Join(grant.ClassificationLabels, ", "), extra))
	case "deny":
		if len(args) < 2 {
			b.reply(msg.ChannelID, "usage: "+prefix+" deny <request-id> [reason]")
			return
		}
		reason := strings.Join(args[2:], " ")
		if _, err := b.manager.Deny(ctx, args[1], "discord:"+msg.Author.ID, reason); err != nil {
			b.reply(msg.ChannelID, "error: "+err.Error())
			return
		}
		b.reply(msg.ChannelID, "Denied `"+args[1]+"`.")
	default:
		b.reply(msg.ChannelID, "unknown command")
	}
}

func (b *Bot) reply(channelID, content string) {
	if b == nil || strings.TrimSpace(content) == "" {
		return
	}
	_, _ = b.session.ChannelMessageSend(channelID, content)
}

func escapeLine(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.TrimSpace(value)
	if value == "" {
		return "(none)"
	}
	if len(value) > 500 {
		return value[:500] + "..."
	}
	return value
}
