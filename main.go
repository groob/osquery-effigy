package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	osquery "github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
	"github.com/pkg/errors"
)

func main() {
	var (
		flSocketPath = flag.String("socket", "", "")
		flTimeout    = flag.Duration("timeout", 0, "")
	)
	flag.Parse()

	// create an extension server. used to register the table plugin.
	server, err := osquery.NewExtensionManagerServer("com.github.groob.effigy", *flSocketPath)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// create an extension client. used to call the core tables.
	client, err := osquery.NewClient(*flSocketPath, *flTimeout)
	if err != nil {
		log.Fatalf("Error creating extension client: %s\n", err)
	}

	// initialize effigy plugin implementation.
	e := &effigy{effigyClient: http.DefaultClient, osqueryClient: client}

	// register the table plugin
	server.RegisterPlugin(e.Table())

	// run the server
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

type effigy struct {
	effigyClient  *http.Client
	osqueryClient *osquery.ExtensionManagerClient
}

func (e *effigy) Table() *table.Plugin {
	columns := []table.ColumnDefinition{
		table.TextColumn("latest_efi_version"),
		table.TextColumn("efi_version"),
		table.TextColumn("efi_version_status"),
		table.TextColumn("latest_os_version"),
		table.TextColumn("os_version"),
		table.TextColumn("os_version_status"),
		table.TextColumn("latest_build_number"),
		table.TextColumn("build_number"),
		table.TextColumn("build_number_status"),
	}

	return table.NewPlugin("effigy", columns, e.generate)
}

// generate would use the underlying http and osquery clients to return the populated columns in the table.
func (e *effigy) generate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// create an API request which is populated from existing osquery tables.
	req, err := e.buildRequest()
	if err != nil {
		return nil, err
	}

	// call the API with a JSON encoded request.
	resp, err := e.callAPI(req)
	if err != nil {
		return nil, err
	}

	// use the API response to create the osquery result row.
	result := []map[string]string{
		map[string]string{
			"latest_efi_version":  resp.LatestEFIVersion.Msg,
			"efi_version":         req.ROMVersion,
			"efi_version_status":  "success",
			"latest_os_version":   resp.LatestOSVersion.Msg,
			"os_version":          req.OSVersion,
			"os_version_status":   "success",
			"latest_build_number": resp.LatestBuildNumber.Msg,
			"build_number":        req.BuildNumber,
			"build_number_status": "success",
		},
	}
	return result, nil
}

type effigyRequest struct {
	BoardID         string `json:"board_id"`
	SMCVersion      string `json:"smc_ver"`
	BuildNumber     string `json:"build_num"`
	ROMVersion      string `json:"rom_ver"`
	HardwareVersion string `json:"hw_ver"`
	OSVersion       string `json:"os_ver"`
	SystemUUID      string `json:"sys_uuid"`
	MACAddress      string `json:"mac_addr"`
	HashedUUID      string `json:"hashed_uuid"`
}

type effigyResponse struct {
	LatestEFIVersion  msg `json:"latest_efi_version"`
	LatestOSVersion   msg `json:"latest_os_version"`
	LatestBuildNumber msg `json:"latest_build_number"`
}

type msg struct {
	Msg string `json:"msg"`
}

func (e *effigy) buildRequest() (*effigyRequest, error) {
	systemInfo, err := e.osqueryClient.QueryRow("select * from system_info")
	if err != nil {
		return nil, errors.Wrap(err, "query system info table")
	}

	osVersion, err := e.osqueryClient.QueryRow("select * from os_version")
	if err != nil {
		return nil, errors.Wrap(err, "query os_version table")
	}
	smcRaw, err := e.osqueryClient.QueryRow(`select value from smc_keys where key = 'RVBF'`)
	if err != nil {
		return nil, errors.Wrap(err, "query smc_keys table")
	}

	platformInfo, err := e.osqueryClient.QueryRow(`select * from platform_info`)
	if err != nil {
		return nil, errors.Wrap(err, "query smc_keys table")
	}

	request := &effigyRequest{
		BuildNumber:     osVersion["build"],
		SMCVersion:      smcRaw["value"],
		HardwareVersion: systemInfo["hardware_model"],
		OSVersion:       osVersion["version"],
		ROMVersion:      platformInfo["version"],
		MACAddress:      "b4:bf:b4:b1:b6:bc",                    // TODO
		SystemUUID:      "12345678-1234-1234-1234-1234567890AB", // TODO
		HashedUUID:      "foobar",                               // TODO
		BoardID:         "Mac-66E35819EE2D0D05",                 // TODO
	}
	return request, nil
}

const apiURL = "https://api.efigy.io/apple/oneshot"

func (e *effigy) callAPI(request *effigyRequest) (*effigyResponse, error) {
	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(request); err != nil {
		return nil, err
	}
	resp, err := e.effigyClient.Post(apiURL, "application/json", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(os.Stderr, resp.Body)
		return nil, fmt.Errorf("got %s from effigy api", resp.Status)
	}

	var response effigyResponse
	if json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return &response, nil
}
