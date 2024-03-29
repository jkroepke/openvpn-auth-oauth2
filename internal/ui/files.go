package ui

import "embed"

//go:embed assets/*
var Static embed.FS

//go:embed index.gohtml
var Template embed.FS
