#pragma once


typedef struct {
	mr_config* config;
	void(*next)(int status, mr_ctx mr_ctx);
} _mr_ctx;