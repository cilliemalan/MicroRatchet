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

static ptrdiff_t action_id_counter = 0;

struct t_action {

	// action identifier used to prevent use-after-free
	// and also reference counting
	size_t id;

	// the action to perform
	uint32_t naction;

	// a buffer for data
	uint8_t* data;

	// the size of the data
	uint32_t size;

	// the size of the buffer for sending
	uint32_t space_available;

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

	// used to track whether or not to include ECDH parameters
	uint32_t message_nr;

	// the notication waited upon and notified
	// when actions are enqueued
	void* action_notify;

	// stored notification for when 
	// initialization is complete
	void* initialize_notify;

	// the buffer used for initialization messages
	uint8_t* initialize_buffer;

	// the result of initialization
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

static mr_result hl_action_add(mr_ctx _ctx, int naction, const uint8_t* data, uint32_t amount, uint32_t timeout)
{
	_mr_ctx* ctx = (_mr_ctx*)_ctx;
	FAILIF(!ctx, MR_E_INVALIDARG, "ctx must be provided");
	FAILIF(!ctx->highlevel, MR_E_INVALIDOP, "The high level event loop is not running");
	hlctx* hl = (hlctx*)ctx->highlevel;

	mr_result result = MR_E_SUCCESS;
	size_t actionid = (size_t)ATOMIC_INCREMENT(action_id_counter);

	// copy argument data
	action* newact;
	if (naction == HL_ACTION_SEND)
	{
		// check
		FAILIF(!data, MR_E_INVALIDARG, "data must be provided");
		FAILIF(!amount, MR_E_INVALIDARG, "amount must be greater than zero");

		// we allocate a buffer slightly bigger for header, padding and (sometimes) ECDH
		// we do it here because otherwise we would need to allocate AGAIN later.
		uint32_t space_available = amount + OVERHEAD_WITH_ECDH;
		if (space_available < MIN_MESSAGE_SIZE_WITH_ECDH)
		{
			space_available = MIN_MESSAGE_SIZE_WITH_ECDH;
		}
		space_available = quantize(space_available, hl->config->message_quantization);

		// allocate space for the message and its data
		uint8_t* buffer;
		_C(mr_allocate(ctx, sizeof(action) + space_available, &buffer));
		newact = (action*)buffer;
		newact->data = buffer + sizeof(action);
		newact->size = amount;
		newact->space_available = space_available;

		// copy in data
		mr_memcpy(newact->data, data, amount);
	}
	else if (naction == HL_ACTION_RECEIVE_DATA || naction == HL_ACTION_RECEIVE)
	{
		// check
		FAILIF(!amount, MR_E_INVALIDARG, "amount must be greater than zero");
		if (naction == HL_ACTION_RECEIVE_DATA)
		{
			FAILIF(!data, MR_E_INVALIDARG, "data must be provided");
		}

		uint32_t spaceavailable = amount;
		if (!ctx->init.initialized && amount < 256)
		{
			// during initialization, larger buffers
			// are needed for response messages
			spaceavailable = 256;
		}

		// allocate space for the action and arguments
		uint8_t* buffer;
		_C(mr_allocate(ctx, sizeof(action) + spaceavailable, &buffer));
		newact = (action*)buffer;
		newact->data = buffer + sizeof(action);
		newact->size = amount;
		newact->space_available = spaceavailable;

		if (naction == HL_ACTION_RECEIVE_DATA)
		{
			// copy in data if we have it already
			mr_memcpy(newact->data, data, amount);
		}
	}
	else if (naction == HL_ACTION_NONE || naction == HL_ACTION_TERMINATE || naction == HL_ACTION_INITIALIZE)
	{
		// just allocate the action
		_C(mr_allocate(ctx, sizeof(action), &newact));
	}
	else
	{
		FAILMSG(MR_E_INVALIDARG, "Invalid action");
	}

	// setup other action paramters
	newact->id = actionid << 4;
	newact->naction = naction;
	newact->next = 0;
	newact->result = MR_E_SUCCESS;
	newact->timeout = false;

	if (timeout == 0)
	{
		newact->notify = 0;
		TRACEMSGCTX(ctx, "####enqueueing action without waiting");
		hl_action_enqueue(&hl->head, newact);
		TRACEMSGCTX(ctx, "--->notify hl->action_notify");
		hl->config->notify(hl->config->user, hl->action_notify);
		result = MR_E_ACTION_ENQUEUED;
	}
	else
	{
		// id doubles as a reference counter
		// if action is HL_ACTION_TERMINATE the
		// main loop must free otherwise we
		// free if we wait on the action
		if (naction != HL_ACTION_TERMINATE)
		{
			newact->id++;
		}

		// create a wait handle for the action
		newact->notify = hl->config->create_wait_handle(hl->config->user);

		// enqueue the action
		TRACEMSGCTX(ctx, "####enqueueing action");
		hl_action_enqueue(&hl->head, newact);
		TRACEMSGCTX(ctx, "--->notify hl->action_notify");
		hl->config->notify(hl->config->user, hl->action_notify);

		// block until the action is completed or timed out
		bool wait_success = hl->config->wait(hl->config->user, newact->notify, timeout);

		TRACEMSGCTX(ctx, "####action completed");

		// return the result of the action
		if (wait_success)
		{
			result = newact->result;
			
			// atomic decrement to decide who frees the action.
			// terminate must be freed by the main loop because
			// it will destroy the hl context soon after, meaning
			// it will be invalid below.
			if (naction != HL_ACTION_TERMINATE && !(ATOMIC_DECREMENT(newact->id) & 0xf))
			{
				TRACEMSGCTX(ctx, "####free item from outside mainloop");
				// we need to free
				hl->config->destroy_wait_handle(hl->config->user, newact->notify);
				mr_free(ctx, newact);
			}
		}
		else
		{
			// atomic decrement to decide who frees the action.
			// terminate must be freed by the main loop because
			// it will destroy the hl context soon after, meaning
			// it will be invalid below.
			if (naction != HL_ACTION_TERMINATE && !(ATOMIC_DECREMENT(newact->id) & 0xf))
			{
				TRACEMSGCTX(ctx, "####free item from outside mainloop");
				// we need to free
				hl->config->destroy_wait_handle(hl->config->user, newact->notify);
				mr_free(ctx, newact);
			}
			else if ((newact->id & (~((size_t)0xf))) == naction)
			{
				// very slim chance of use after free. The sceduler would have
				// to break on the line of this comment and run until after
				// newact has been freed and something else allocated in its place
				// before returning.
				newact->timeout = true;
			}

			result = MR_E_TIMEOUT;
		}
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

	// assign hl structure
	hlctx hl;
	FAILIF(ATOMIC_COMPARE_EXCHANGE(ctx->highlevel, &hl, 0) != 0,
		MR_E_INVALIDOP,
		"mr_hl_mainloop can only be called once for a given context");

	// configure hl structure
	mr_memzero(&hl, sizeof(hlctx));
	hl.config = config;
	hl.action_notify = config->create_wait_handle(config->user);

	TRACEMSGCTX(ctx, "****entering high level loop");
	bool active = true;
	while (active)
	{
		uint32_t timeout = 0xffffffff;
		action* item = hl_action_dequeue(&hl.head);

		if (item)
		{
			bool initialize_notify = false;

			// TODO: there is a possiblity that
			// the item could have been freed between
			// the above line and the below line.
			ATOMIC_INCREMENT(item->id);
			mr_result result = MR_E_SUCCESS;

			if (!item->timeout)
			{
				// execute the action
				switch (item->naction)
				{
				case HL_ACTION_NONE:
				{
					TRACEMSGCTX(ctx, "****dequeued NONE action");
				}
				break;
				case HL_ACTION_INITIALIZE:
				{
					TRACEMSGCTX(ctx, "****dequeued INITIALIZE action");
					if (hl.initialize_buffer)
					{
						mr_free(ctx, hl.initialize_buffer);
					}
					result = mr_allocate(ctx, 256, &hl.initialize_buffer);
					if (result == MR_E_SUCCESS)
					{
						result = mr_ctx_initiate_initialization(ctx, hl.initialize_buffer, 256, true);

						if (result == MR_E_SENDBACK)
						{
							if (hl.config->transmit(hl.config->user, hl.initialize_buffer, 256) == 256)
							{
								// that's it. Now we wait
							}
							else
							{
								DEBUGMSG("Transmit failed");
								result = MR_E_FAIL;
							}
						}
					}

					if (result < 0)
					{
						initialize_notify = true;
						hl.initialize_result = result;
					}
				}
				break;
				case HL_ACTION_SEND:
				{
					TRACEMSGCTX(ctx, "****dequeued SEND action");
					if (!ctx->init.initialized)
					{
						DEBUGMSG("Cannot send before initialization has completed");
						result = MR_E_INVALIDOP;
					}
					else
					{
						bool ecdh = hl.config->ecdh_frequency <= 1 ? true : (++hl.message_nr) % hl.config->ecdh_frequency;
						uint32_t space_available = item->space_available;
						if (!ecdh)
						{
							// the message size is already padded at least MIN_MESSAGE_SIZE
							space_available -= ECNUM_SIZE;
						}
						result = mr_ctx_send(ctx, item->data, item->size, space_available);
						if (result == MR_E_SUCCESS)
						{
							result = config->transmit(config->user, item->data, space_available) == space_available
								? MR_E_SUCCESS
								: MR_E_FAIL;
						}

						if (result == MR_E_SUCCESS)
						{
							break;
						}
					}
				}
				break;
				case HL_ACTION_RECEIVE:
				{
					TRACEMSGCTX(ctx, "****dequeued RECEIVE action");
					// for RECEIVE we call receive
					if (config->receive(config->user, item->data, item->size) != item->size)
					{
						result = MR_E_FAIL;
					}
				}
				// CASE FALL THROUGH -->
				case HL_ACTION_RECEIVE_DATA:
				{
					if (item->naction == HL_ACTION_RECEIVE_DATA)
					{
						TRACEMSGCTX(ctx, "****dequeued RECEIVE_DATA action");
					}

					if (result == MR_E_SUCCESS)
					{
						bool initdonebefore = ctx->init.initialized;
						// process the received data
						uint32_t data_received_size;
						uint8_t* payload = 0;
						result = mr_ctx_receive(ctx,
							item->data,
							item->size,
							item->space_available,
							&payload,
							&data_received_size);

						if (result == MR_E_SUCCESS)
						{
							// call the data callback
							if (config->data_callback && data_received_size)
							{
								TRACEMSGCTX(ctx, "****invoking data callback");
								config->data_callback(config->user, payload, data_received_size);
							}
							else
							{
								TRACEMSGCTX(ctx, "****NOT invoking data callback");
							}
						}
						else if (result == MR_E_SENDBACK)
						{
							TRACEMSGCTX(ctx, "****transmitting sendback data");
							// we need to send an initialization response
							if (config->transmit(config->user, payload, data_received_size) != data_received_size)
							{
								DEBUGMSG("transmission of sendback data failed");
								// if the transmit fails, the whole initialization process needs
								// to start over. We rely on a timeout to make this happen.
								result = MR_E_FAIL;
							}
						}

						// check if initialization is done
						if (ctx->init.initialized && !initdonebefore)
						{
							TRACEMSGCTX(ctx, "****initialization completed");
							if (hl.initialize_notify)
							{
								TRACEMSGCTX(ctx, "****notifying initialization is complete");
								initialize_notify = true;
								hl.initialize_result = MR_E_SUCCESS;
							}
							mr_free(ctx, hl.initialize_buffer);
						}
					}
				}
				break;
				case HL_ACTION_TERMINATE:
				{
					TRACEMSGCTX(ctx, "****dequeued TERMINATE action");
					active = false;
				}
				break;
				default:
				{
					TRACEMSGCTX(ctx, "****dequeued INVALID action");
				}
				break;
				}

				// set the result
				item->result = result;

				// notify that the action is completed
				if (item->notify)
				{
					TRACEMSGCTX(ctx, "--->item->notify");
					config->notify(config->user, item->notify);
				}

				// we need to notify this after the one above because
				// it works like an action complete notification.
				if (initialize_notify)
				{
					TRACEMSGCTX(ctx, "--->hl.initialize_notify");
					hl.config->notify(hl.config->user, hl.initialize_notify);
				}
			}
			else
			{
				TRACEMSGCTX(ctx, "****dequeued timed out action");
			}

			// the atomic decrement is to ensure the item is not double freed.
			// terminate must be freed here.
			if (item->naction == HL_ACTION_TERMINATE || !(ATOMIC_DECREMENT(item->id) & 0xf))
			{
				TRACEMSGCTX(ctx, "####free item inside mainloop");
				item->id = 0;
				config->destroy_wait_handle(config->user, item->notify);
				mr_free(ctx, item);
			}
		}
		else
		{
			TRACEMSGCTX(ctx, "****waiting for action");
			config->wait(config->user, hl.action_notify, 0xffffffff);
		}
	}

	TRACEMSGCTX(ctx, "exiting main loop");

	// destroy the wait handle
	void* ntfy = hl.action_notify;
	hl.action_notify = 0;
	hl.config->destroy_wait_handle(hl.config->user, ntfy);

	// remove the high level structure
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

	TRACEMSGCTX(ctx, "####enqueueing INITIALIZE action");
	mr_result result = hl_action_add(_ctx, HL_ACTION_INITIALIZE, 0, 0, 0);
	if (result == MR_E_ACTION_ENQUEUED)
	{
		if (hl->config->wait(hl->config->user, wh, timeout))
		{
			result = MR_E_SUCCESS;
		}
		else
		{
			result = MR_E_TIMEOUT;
		}

		hl->initialize_notify = 0;
		hl->config->destroy_wait_handle(hl->config->user, wh);
		return result;
	}
	else
	{
		hl->config->destroy_wait_handle(hl->config->user, wh);
		FAILMSG(result, "Failed to enqueue initialize action");
	}
}

mr_result mr_hl_send(mr_ctx ctx, const uint8_t* data, const uint32_t size, uint32_t timeout)
{
	TRACEMSGCTX(ctx, "####enqueueing SEND action");
	return hl_action_add(ctx, HL_ACTION_SEND, data, size, timeout);
}

mr_result mr_hl_receive(mr_ctx ctx, uint32_t available, uint32_t timeout)
{
	TRACEMSGCTX(ctx, "####enqueueing RECEIVE action");
	return hl_action_add(ctx, HL_ACTION_RECEIVE, 0, available, timeout);
}

mr_result mr_hl_receive_data(mr_ctx ctx, const uint8_t* data, uint32_t size, uint32_t timeout)
{
	TRACEMSGCTX(ctx, "####enqueueing RECEIVE_DATA action");
	return hl_action_add(ctx, HL_ACTION_RECEIVE_DATA, data, size, timeout);
}

mr_result mr_hl_deactivate(mr_ctx ctx, uint32_t timeout)
{
	TRACEMSGCTX(ctx, "####enqueueing TERMINATE action");
	return hl_action_add(ctx, HL_ACTION_TERMINATE, 0, 0, timeout);
}
