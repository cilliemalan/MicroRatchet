#include "pch.h"
#include "internal.h"

// the amount of time to wait for action during initialization
#define INITIALIZE_TIMEOUT 30000

#define HL_ACTION_NONE 0
#define HL_ACTION_SEND 1
#define HL_ACTION_RECEIVE 2
#define HL_ACTION_RECEIVE_DATA 3
#define HL_ACTION_TERMINATE 4
#define HL_ACTION_INITIALIZE 5

#define HL_STATE_UNINITIALIZED 0
#define HL_STATE_INITIALIZING 1
#define HL_STATE_INITIALIZED 2

typedef struct t_senddata {
	// pointer to the buffer
	uint8_t* data;
	// the size of the data
	uint32_t size;
	// the size of the buffer (needs to be larger)
	uint32_t messagesize;
} senddata;

typedef struct t_receivedata {
	// data received
	uint8_t* data;
	// amount of data
	uint32_t size;
} receivedata;

struct t_action {
	// the action to perform
	uint32_t naction;

	// arguments for the action
	union {
		// the data to send
		senddata* senddata;

		// the received data
		receivedata* receivedata;

		// the amount of data available if receive is called
		uint32_t receiveamount;
	};

	// if set, notify will be called with this argument
	void* notify;

	// the result of the action
	mr_result result;

	// if true, the action is considered to have timed out and will not be executed
	bool timeout;

	// the next action to perform
	struct t_action* next;
};
typedef struct t_action action;

typedef struct t_hlctx {

	// the main action list
	action* head;

	// configuration passed to mr_hl_mainloop
	const mr_hl_config* config;

	uint32_t message_nr;

	int state;

	void* initialize_notify;
	uint8_t* initialize_buffer;
	mr_result initialize_result;
} hlctx;

static uint32_t quantize(uint32_t size, uint32_t multiple)
{
	if (multiple <= 1)
	{
		return size;
	}
	else
	{
		int r = size % multiple;
		return r ? size + multiple - r : size;
	}
}

static action* hl_action_dequeue(action** phead)
{
	action* act = *phead;
	while (act)
	{
		// replace the head if the head remains the head
		if ((action*)ATOMIC_COMPARE_EXCHANGE(*phead, act->next, act) == act)
		{
			act->next = 0;
			break;
		}

		act = *phead;
	}

	return act;
}

static void hl_action_enqueue(action** phead, action* act)
{
	for (;;)
	{
		action* head = *phead;
		if (!head)
		{
			// this item is will be the first in the list
			if (ATOMIC_COMPARE_EXCHANGE(*phead, act, 0) == 0)
			{
				break;
			}
		}
		else
		{
			// find the tail
			action* item = head;
			while (item->next) item = item->next;

			// tack on the new item if the tail remains the tail
			if (ATOMIC_COMPARE_EXCHANGE(item->next, act, 0) == 0)
			{
				// if the head changed we tacked it onto the wrong list
				if (*phead != head)
				{
					item->next = 0;
					break;
				}
			}
		}
	}
}

static mr_result hl_action_add(mr_ctx _ctx, action* act, uint32_t timeout)
{
	_mr_ctx* ctx = (_mr_ctx*)_ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "ctx must be provided");
	FAILIF(!ctx->highlevel, MR_E_INVALIDOP, "The high level event loop is not running");
	hlctx* hl = (hlctx*)ctx->highlevel;

	mr_result result = MR_E_SUCCESS;

	// clone the action
	action* newact;
	_C(mr_allocate(ctx, sizeof(action), &newact));
	newact->naction = act->naction;
	newact->notify = 0;

	// copy argument data
	if (newact->naction == HL_ACTION_SEND)
	{
		senddata* newsenddata;
		_R(result, mr_allocate(ctx, sizeof(senddata), &newsenddata));

		if (result == MR_E_SUCCESS)
		{
			// we allocate a buffer slightly bigger for header, padding and (sometimes) ECDH
			// we do it here because otherwise we would need to allocate AGAIN.
			newsenddata->messagesize = act->senddata->messagesize + OVERHEAD_WITH_ECDH;
			if (newsenddata->messagesize < MIN_MESSAGE_SIZE_WITH_ECDH)
			{
				newsenddata->messagesize = MIN_MESSAGE_SIZE_WITH_ECDH;
			}
			newsenddata->messagesize = quantize(newsenddata->messagesize, hl->config->message_quantization);

			// copy data
			_R(result, mr_allocate(ctx, newsenddata->messagesize, &newsenddata->data));
			if (result == MR_E_SUCCESS)
			{
				mr_memcpy(newsenddata->data, act->senddata->data, act->senddata->size);

				newsenddata->size = act->senddata->size;

				newact->senddata = newsenddata;
			}
			else
			{
				mr_free(ctx, newsenddata);
			}
		}
	}
	else if (newact->naction == HL_ACTION_RECEIVE)
	{
		newact->receiveamount = act->receiveamount;
	}
	else if (newact->naction == HL_ACTION_RECEIVE_DATA)
	{
		receivedata* newreceivedata;
		_R(result, mr_allocate(ctx, sizeof(receivedata), &newreceivedata));

		// copy data
		_R(result, mr_allocate(ctx, act->receivedata->size, &newreceivedata->data));
		if (result == MR_E_SUCCESS)
		{
			newreceivedata->size = act->receivedata->size;
			mr_memcpy(newreceivedata->data, act->receivedata->data, newreceivedata->size);

			newact->receivedata = newreceivedata;
		}
		else
		{
			mr_free(ctx, newreceivedata);
		}
	}

	if (result == MR_E_SUCCESS)
	{
		if (timeout == 0)
		{
			hl_action_enqueue(&hl->head, newact);
			result = MR_E_ACTION_ENQUEUED;
		}
		else
		{
			newact->notify = hl->config->create_wait_handle(hl->config->user);
			hl_action_enqueue(&hl->head, newact);
			bool wait_success = hl->config->wait(newact->notify, timeout, hl->config->user);
			if (wait_success)
			{
				result = newact->result;
			}
			else
			{
				// TODO: possible use after free
				newact->timeout = true;
				result = MR_E_TIMEOUT;
			}
		}
	}
	else
	{
		mr_free(ctx, newact);
	}

	return result;
}

mr_result mr_hl_mainloop(mr_ctx _ctx, const mr_hl_config* config)
{
	_mr_ctx* ctx = (_mr_ctx*)_ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "ctx must be provided");
	FAILIF(!config, MR_E_INVALIDARG, "config must be provided");
	FAILIF(!ctx->identity, MR_E_INVALIDOP, "context identity must be set before calling mainloop");
	FAILIF(!(config->create_wait_handle && config->wait && config->notify &&
		config->transmit &&
		config->checkkey_callback),
		MR_E_INVALIDARG,
		"all callbacks must be provided");
	FAILIF(ctx->highlevel, MR_E_INVALIDOP, "mr_hl_mainloop can only be called once for a given context");

	_C(mr_allocate(ctx, sizeof(hlctx), &ctx->highlevel));
	mr_memzero(ctx->highlevel, sizeof(hlctx));
	hlctx* hl = (hlctx*)ctx->highlevel;
	hl->config = config;

	void* wh = config->create_wait_handle(config->user);
	bool active = true;
	while (active)
	{
		uint32_t timeout = hl->state == HL_STATE_INITIALIZING ? INITIALIZE_TIMEOUT : 0xffffffff;

		action* item = hl_action_dequeue(&hl->head);

		if (item)
		{
			mr_result result = MR_E_SUCCESS;

			if (!item->timeout)
			{
				uint8_t* data_received = 0;
				uint32_t data_received_size = 0;
				uint32_t data_received_spaceavailable = 0;

				// execute the action
				switch (item->naction)
				{
				case HL_ACTION_NONE:
					break;
				case HL_ACTION_INITIALIZE:
				{
					hl->state = HL_STATE_INITIALIZING;
					if (hl->initialize_buffer)
					{
						mr_free(ctx, hl->initialize_buffer);
					}
					result = mr_allocate(ctx, 256, &hl->initialize_buffer);
					if (result == MR_E_SUCCESS)
					{
						result = mr_ctx_initiate_initialization(ctx, hl->initialize_buffer, 256, true);

						if (result == MR_E_SUCCESS)
						{
							if (hl->config->transmit(hl->initialize_buffer, 256, hl->config->user) == 256)
							{
								// that's it. Now we wait
							}
							else
							{
								MRMSG("transmit failed");
								result = MR_E_FAIL;
							}
						}
					}

					if (result != MR_E_SUCCESS)
					{
						hl->initialize_result = result;
						hl->config->notify(hl->initialize_notify, hl->config->user);
						hl->state = HL_STATE_UNINITIALIZED;
					}
				}
				break;
				case HL_ACTION_SEND:
				{
					if (hl->state != HL_STATE_INITIALIZED)
					{
						MRMSG("Cannot send before initialization has completed");
						result = MR_E_INVALIDOP;
					}
					else
					{
						for (uint32_t i = 0; i <= config->num_retries; i++)
						{
							bool ecdh = hl->config->ecdh_frequency <= 1 ? true : (++hl->message_nr) % hl->config->ecdh_frequency;
							uint32_t messagesize = item->senddata->messagesize;
							if (!ecdh)
							{
								// the message size is padded at least MIN_MESSAGE_SIZE
								messagesize -= ECNUM_SIZE;
							}
							result = mr_ctx_send(ctx, item->senddata->data, item->senddata->size, messagesize);
							if (result == MR_E_SUCCESS)
							{
								result = config->transmit(item->senddata->data, messagesize, config->user) == messagesize
									? MR_E_SUCCESS
									: MR_E_FAIL;
							}

							if (result == MR_E_SUCCESS)
							{
								break;
							}
						}
					}
				}
				break;
				case HL_ACTION_RECEIVE:
				case HL_ACTION_RECEIVE_DATA:
				{
					// get the amount of data
					if (item->naction == HL_ACTION_RECEIVE)
					{
						data_received_size = item->receiveamount;
					}
					else
					{
						data_received_size = item->receivedata->size;
					}

					// the amount of space needed in the buffer is larger for init messages
					data_received_spaceavailable = data_received_size;
					if (hl->state != HL_STATE_INITIALIZED && data_received_spaceavailable < 256)
					{
						data_received_spaceavailable = 256;
					}

					// allocate the buffer for received data
					result = mr_allocate(ctx, data_received_spaceavailable, &data_received);
					if (result == MR_E_SUCCESS)
					{
						if (item->naction == HL_ACTION_RECEIVE)
						{
							// for RECEIVE we call receive
							if (config->receive(data_received, data_received_size, config->user) != data_received_size)
							{
								result = MR_E_FAIL;
							}
						}
						else
						{
							// for RECEIVE_DATA we copy
							mr_memcpy(data_received, item->receivedata->data, data_received_size);
						}
					}
				}
				break;
				case HL_ACTION_TERMINATE:
					active = false;
					break;
				}

				// process data that may have come in
				if (data_received)
				{
					uint8_t* payload = 0;
					result = mr_ctx_receive(ctx,
						data_received,
						data_received_size,
						data_received_spaceavailable,
						&payload,
						&data_received_size);
					if (result == MR_E_SUCCESS)
					{
						if (hl->state == HL_STATE_INITIALIZING)
						{
							hl->state = HL_STATE_INITIALIZED;
							void* initnotify = hl->initialize_notify;
							if (initnotify)
							{
								hl->config->notify(initnotify, hl->config->user);
							}
						}
						else
						{
							// call the data callback
							if (config->data_callback && data_received_size)
							{
								config->data_callback(payload, data_received_size, config->user);
							}
						}
					}
					else if (result == MR_E_SENDBACK)
					{
						// we need to send an initialization response
						if (config->transmit(payload, data_received_size, config->user) != data_received_size)
						{
							// if the transmit fails, the whole initialization process needs
							// to start over. We rely on a timeout to make this happen
							result = MR_E_FAIL;
						}
					}

					mr_free(ctx, data_received);
				}

				// set the result
				item->result = result;

				// notify that the action is completed
				if (item->notify)
				{
					config->notify(item->notify, config->user);
				}
			}

			// free the item
			if (item->naction == HL_ACTION_SEND && item->senddata)
			{
				mr_free(ctx, item->senddata->data);
				mr_free(ctx, item->senddata);
			}
			else if (item->naction == HL_ACTION_RECEIVE_DATA && item->receivedata)
			{
				mr_free(ctx, item->receivedata->data);
				mr_free(ctx, item->receivedata);
			}

			mr_free(ctx, item);
		}
		else
		{
			config->wait(wh, 0xffffffff, config->user);
		}
	}

	ctx->highlevel = 0;

	return MR_E_SUCCESS;
}

mr_result mr_hl_initialize(mr_ctx _ctx, uint32_t timeout)
{
	_mr_ctx* ctx = (_mr_ctx*)_ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "ctx must be provided");
	FAILIF(!ctx->highlevel, MR_E_INVALIDOP, "The high level event loop is not running");
	hlctx* hl = (hlctx*)ctx->highlevel;
	FAILIF(hl->initialize_notify, MR_E_INVALIDOP, "initialization already in process");
	void* wh = hl->config->create_wait_handle(hl->config->user);
	
	hl->initialize_notify = wh;

	action newaction = {
		.naction = HL_ACTION_INITIALIZE
	};
	mr_result result = hl_action_add(_ctx, &newaction, 0);
	if (result == MR_E_ACTION_ENQUEUED)
	{
		if (hl->config->wait(wh, timeout, hl->config->user))
		{
			result = MR_E_SUCCESS;
		}
		else
		{
			result = MR_E_TIMEOUT;
		}
	}
	else
	{
		hl->config->wait(wh, 0, hl->config->user);
	}

	hl->initialize_notify = 0;
	return result;
}

mr_result mr_hl_send(mr_ctx _ctx, const uint8_t* data, const uint32_t size, const uint32_t messagesize, uint32_t timeout)
{
	senddata actiondata = {
		.data = (uint8_t*)data,
		.size = size,
		.messagesize = messagesize,
	};
	action newaction = {
		.naction = HL_ACTION_SEND,
		.senddata = &actiondata
	};
	return hl_action_add(_ctx, &newaction, timeout);
}

mr_result mr_hl_receive(mr_ctx _ctx, uint32_t available, uint32_t timeout)
{
	action newaction = {
		.naction = HL_ACTION_RECEIVE,
		.receiveamount = available
	};
	return hl_action_add(_ctx, &newaction, timeout);
}

mr_result mr_hl_receive_data(mr_ctx _ctx, const uint8_t* data, uint32_t size, uint32_t timeout)
{
	receivedata actiondata = {
		.data = (uint8_t*)data,
		.size = size
	};
	action newaction = {
		.naction = HL_ACTION_RECEIVE,
		.receivedata = &actiondata
	};
	return hl_action_add(_ctx, &newaction, timeout);
}

mr_result mr_hl_deactivate(mr_ctx _ctx, uint32_t timeout)
{
	action newaction = { .naction = HL_ACTION_TERMINATE };
	return hl_action_add(_ctx, &newaction, timeout);
}
