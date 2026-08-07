// Package main manages the public RustyAuth site on Cloudflare.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/pulumi/pulumi-cloudflare/sdk/v6/go/cloudflare"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		accountID := strings.TrimSpace(os.Getenv("CLOUDFLARE_ACCOUNT_ID"))
		if accountID == "" {
			return fmt.Errorf("CLOUDFLARE_ACCOUNT_ID is required")
		}
		dnsToken := strings.TrimSpace(os.Getenv("CLOUDFLARE_DNS_API_TOKEN"))
		if dnsToken == "" {
			return fmt.Errorf("CLOUDFLARE_DNS_API_TOKEN is required")
		}

		cfg := config.New(ctx, "rustyauth-cloudflare")
		projectName := cfg.Require("projectName")
		zoneName := cfg.Require("zoneName")
		domainName := cfg.Require("domainName")

		dnsProvider, err := cloudflare.NewProvider(ctx, "cloudflare-dns", &cloudflare.ProviderArgs{
			ApiToken: pulumi.String(dnsToken),
		})
		if err != nil {
			return fmt.Errorf("creating DNS provider: %w", err)
		}

		zone, err := cloudflare.LookupZone(ctx, &cloudflare.LookupZoneArgs{
			Filter: &cloudflare.GetZoneFilter{Name: &zoneName, Match: "all"},
		}, pulumi.Provider(dnsProvider))
		if err != nil {
			return fmt.Errorf("looking up Cloudflare zone %q: %w", zoneName, err)
		}

		project, err := cloudflare.NewPagesProject(ctx, "rustyauth-site", &cloudflare.PagesProjectArgs{
			AccountId:        pulumi.String(accountID),
			Name:             pulumi.String(projectName),
			ProductionBranch: pulumi.String("main"),
		})
		if err != nil {
			return fmt.Errorf("creating Pages project: %w", err)
		}

		_, err = cloudflare.NewDnsRecord(ctx, "rustyauth-site-dns", &cloudflare.DnsRecordArgs{
			ZoneId:  pulumi.String(zone.ZoneId),
			Name:    pulumi.String(domainName),
			Type:    pulumi.String("CNAME"),
			Content: project.Subdomain,
			Proxied: pulumi.Bool(true),
			Ttl:     pulumi.Float64(1),
			Comment: pulumi.String("RustyAuth open-source site — Cloudflare Pages"),
		}, pulumi.Provider(dnsProvider))
		if err != nil {
			return fmt.Errorf("creating Pages DNS record: %w", err)
		}

		domain, err := cloudflare.NewPagesDomain(ctx, "rustyauth-site-domain", &cloudflare.PagesDomainArgs{
			AccountId:   pulumi.String(accountID),
			ProjectName: project.Name,
			Name:        pulumi.String(domainName),
		})
		if err != nil {
			return fmt.Errorf("attaching Pages domain: %w", err)
		}

		ctx.Export("pagesProject", project.Name)
		ctx.Export("pagesSubdomain", project.Subdomain)
		ctx.Export("customDomain", domain.Name)
		ctx.Export("customDomainStatus", domain.Status)
		return nil
	})
}
