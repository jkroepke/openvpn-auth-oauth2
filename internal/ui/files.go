package ui

import "embed"

//go:embed static/*
var Static embed.FS

//go:embed index.gohtml
var Template embed.FS
