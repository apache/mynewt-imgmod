/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/apache/mynewt-artifact/errors"

	"mynewt.apache.org/imgmod/cli"
	"mynewt.apache.org/imgmod/iutil"
	"mynewt.apache.org/imgmod/version"
)

func main() {
	imgmodHelpText := ""
	imgmodHelpEx := ""

	logLevelStr := ""
	imgmodCmd := &cobra.Command{
		Use:     "imgmod",
		Short:   "imgmod is a tool to view and modify Mynewt image files",
		Long:    imgmodHelpText,
		Example: imgmodHelpEx,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logLevel, err := log.ParseLevel(logLevelStr)
			if err != nil {
				cli.ImgmodUsage(nil, errors.Wrapf(err, "failed to parse log level"))
			}
			log.SetLevel(logLevel)
		},

		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	imgmodCmd.PersistentFlags().BoolVarP(&iutil.Verbose, "verbose", "v", false,
		"Enable verbose output when executing commands")
	imgmodCmd.PersistentFlags().BoolVarP(&iutil.Quiet, "quiet", "q", false,
		"Be quiet; only display error output")
	imgmodCmd.PersistentFlags().StringVarP(&logLevelStr, "loglevel", "l",
		"WARN", "Log level")

	versHelpText := `Display the imgmod version number`
	versHelpEx := "  imgmod version"
	versCmd := &cobra.Command{
		Use:     "version",
		Short:   "Display the imgmod version number",
		Long:    versHelpText,
		Example: versHelpEx,
		Run: func(cmd *cobra.Command, args []string) {
			iutil.Printf("imgmod %s\n", version.VersionStr())
		},
	}
	imgmodCmd.AddCommand(versCmd)

	cli.AddImageCommands(imgmodCmd)
	cli.AddMfgCommands(imgmodCmd)
	cli.AddKeyCommands(imgmodCmd)

	imgmodCmd.Execute()
}
