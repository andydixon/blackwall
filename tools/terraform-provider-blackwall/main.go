// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

// terraform-provider-blackwall — Terraform provider for managing BlackWall
// resources (projects, OAuth clients, claim defaults, webhooks) via the
// admin JSON API. Built on terraform-plugin-framework v1.
//
// Build + install for local testing:
//
//	go build -o terraform-provider-blackwall .
//	mkdir -p ~/.terraform.d/plugins/blackwall.io/identity/blackwall/0.1.0/linux_amd64
//	cp terraform-provider-blackwall ~/.terraform.d/plugins/blackwall.io/identity/blackwall/0.1.0/linux_amd64/
//
// Then in a Terraform config:
//
//	terraform {
//	  required_providers {
//	    blackwall = {
//	      source = "blackwall.io/identity/blackwall"
//	    }
//	  }
//	}
//
//	provider "blackwall" {
//	  host  = "https://auth.example.com"
//	  token = "bw_admin_..."
//	}
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/blackwall/terraform-provider-blackwall/internal/provider"
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "blackwall.io/identity/blackwall",
		Debug:   debug,
	}
	if err := providerserver.Serve(context.Background(), provider.New("0.1.0"), opts); err != nil {
		log.Fatal(err.Error())
	}
}
