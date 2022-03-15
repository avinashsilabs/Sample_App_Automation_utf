/*****************************************************************************/
/*                                                                           */
/*  Function name : ia_mp3_dec_main_process                                  */
/*                                                                           */
/*  Description   : Stacked processing with function pointer selection       */
/*                                                                           */
/*  Inputs        : WORD32 argc (Arguments count)                            */
/*                  pWORD8 argv[] (Argument strings)                         */
/*                                                                           */
/*  Globals       : None                                                     */
/*                                                                           */
/*  Processing    : Stacked processing of multiple components                */
/*                  Loop1: Set params + Mem alloc                            */
/*                  Loop2: Set params + Init process + Get params            */
/*                  Loop3: Execute                                           */
/*                                                                           */
/*  Outputs       : None                                                     */
/*                                                                           */
/*  Returns       : IA_ERRORCODE error_value  (Error value)                  */
/*                                                                           */
/*  Issues        : none                                                     */
/*                                                                           */
/*  Revision history :                                                       */
/*                                                                           */
/*        DD MM YYYY       Author                Changes                     */
/*        29 07 2005       Tejaswi/Vishal        Created                     */
/*                                                                           */
/*****************************************************************************/

/*****************************************************************************/
/* Process select hash defines                                               */
/*****************************************************************************/
//#define DEBUG_ERROR_HANDLER
//#define MP3_DEC_SET_CONFIG_PARAMS
#if RSI_BT_ENABLE
#include "ia_type_def.h"
#include "ia_error_standards.h"
#include "ia_error_handler.h"
#include "ia_apicmd_standards.h"
#include "ia_mp3_dec_config_params.h"
#include "ia_memory_standards.h"
#include "stdint.h"
#include <stdio.h>

#define MAX_MEM_ALLOCS 16

/* Error code */
IA_ERRORCODE err_code = IA_NO_ERROR;
IA_ERRORCODE ia_mp3_dec_api(pVOID p_ia_module_obj,WORD32 i_cmd, WORD32 i_idx, pVOID pv_value);

/*****************************************************************************/
/* Global variables                                                          */
/*****************************************************************************/
pVOID g_pv_arr_alloc_memory[MAX_MEM_ALLOCS];
WORD  g_w_malloc_count;

/*****************************************************************************/
/*                                                                           */
/*  Function name : ia_mp3_dec_get_config_param                              */
/*                                                                           */
/*  Description   : Get config parameters                                    */
/*                                                                           */
/*  Inputs        : pVOID p_ia_process_api_obj (process API obj)             */
/*                  WORD32 argc (Arguments count)                            */
/*                  pWORD8 argv[] (Argument strings)                         */
/*                                                                           */
/*  Globals       : none                                                     */
/*                                                                           */
/*  Processing    : Get config params from API                               */
/*                                                                           */
/*  Outputs       : none                                                     */
/*                                                                           */
/*  Returns       : IA_ERRORCODE error_value  (Error value)                  */
/*                                                                           */
/*  Issues        : none                                                     */
/*                                                                           */
/*  Revision history :                                                       */
/*                                                                           */
/*        DD MM YYYY       Author                Changes                     */
/*        29 07 2005       Ittiam                Created                     */
/*                                                                           */
/*****************************************************************************/

IA_ERRORCODE ia_mp3_dec_get_config_param(
	pVOID p_ia_process_api_obj, pWORD32 pi_samp_freq,
	pWORD32 pi_num_chan, pWORD32 pi_pcm_wd_sz)
{
#ifdef FRDM_K28F			//! To-DO: in future below function should be included independent of platform
													//! Find corresponding keil compatible library and include it
	/* the process API function */
	IA_ERRORCODE (*p_ia_process_api)(pVOID p_ia_process_api_obj,
		WORD32 i_cmd, WORD32 i_idx, pVOID pv_value) = ia_mp3_dec_api;
#endif	
#ifdef DEBUG_ERROR_HANDLER	
	ia_error_info_struct *p_proc_err_info = &ia_mp3_dec_error_info;
#endif
#ifdef FRDM_K28F
	/* Sampling frequency */
	{
		err_code = (*p_ia_process_api)(p_ia_process_api_obj,
			IA_API_CMD_GET_CONFIG_PARAM,
			IA_MP3DEC_CONFIG_PARAM_SAMP_FREQ, pi_samp_freq);
#ifdef DEBUG_ERROR_HANDLER	
		_IA_HANDLE_ERROR(p_proc_err_info,(WORD8 *) "", err_code);
#endif		

	}
	/* Total Number of Channels */
	{
		err_code = (*p_ia_process_api)(p_ia_process_api_obj,
			IA_API_CMD_GET_CONFIG_PARAM,
			IA_MP3DEC_CONFIG_PARAM_NUM_CHANNELS, pi_num_chan);
#ifdef DEBUG_ERROR_HANDLER	
		_IA_HANDLE_ERROR(p_proc_err_info, (WORD8 *)"", err_code);
#endif		
	}
	/* PCM word size */
	{
		err_code = (*p_ia_process_api)(p_ia_process_api_obj,
			IA_API_CMD_GET_CONFIG_PARAM,
			IA_MP3DEC_CONFIG_PARAM_PCM_WDSZ, pi_pcm_wd_sz);
#ifdef DEBUG_ERROR_HANDLER	
		_IA_HANDLE_ERROR(p_proc_err_info, (WORD8 *)"", err_code);
#endif		
	}
#endif	
	return IA_NO_ERROR;
}

/*****************************************************************************/
/*                                                                           */
/*  Function name : ia_mp3_dec_main_process                                  */
/*                                                                           */
/*  Description   : Stacked processing with function pointer selection       */
/*                                                                           */
/*  Inputs        : WORD32 argc (Arguments count)                            */
/*                  pWORD8 argv[] (Argument strings)                         */
/*                                                                           */
/*  Globals       : None                                                     */
/*                                                                           */
/*  Processing    : Stacked processing of multiple components                */
/*                  Loop1: Set params + Mem alloc                            */
/*                  Loop2: Set params + Init process + Get params            */
/*                  Loop3: Execute                                           */
/*                                                                           */
/*  Outputs       : None                                                     */
/*                                                                           */
/*  Returns       : IA_ERRORCODE error_value  (Error value)                  */
/*                                                                           */
/*  Issues        : none                                                     */
/*                                                                           */
/*  Revision history :                                                       */
/*                                                                           */
/*        DD MM YYYY       Author                Changes                     */
/*        29 07 2005       Tejaswi/Vishal        Created                     */
/*                                                                           */
/*****************************************************************************/
extern uint8_t mp3_data[1800] __attribute__((aligned (4)));
uint8_t g_pv_array[128];
uint8_t g_pv_index = 0;
uint8_t g_pv_pers_array[6000];
uint8_t g_pv_sct_array[8000];
extern uint32_t i_bytes_consumed;
extern uint32_t i_out_bytes;
uint8_t mp3_decoder_init = 0;
uint32_t i_total_bytes = 0;
/* API obj */
pVOID pv_ia_process_api_obj;
//uint8_t  sbc_data[297];

IA_ERRORCODE ia_mp3_dec_main_process(
	uint8_t* in_buf,
	uint8_t* out_buf,
  uint32_t i_buff_size
)
{
  LOOPIDX i;


	/* First part                                        */
	/* Error Handler Init                                */
	/* Get Library Name, Library Version and API Version */
	/* Initialize API structure + Default config set     */
	/* Set config params from user                       */
	/* Initialize memory tables                          */
	/* Get memory information and allocate memory        */

	/* Memory variables */
	UWORD32 n_mems, ui_rem;
	UWORD32 ui_proc_mem_tabs_size;

	/* API size */
	UWORD32 pui_ap_isize;

	/* Process initing done query variable */
	UWORD32 ui_exec_done;
//	UWORD32 need_more_bits = 0;

  //WORD32 i_bytes_consumed;
	//WORD32 i_out_bytes;
	WORD32 i_samp_freq, i_num_chan, i_pcm_wd_sz;

	/* The process API function */
	IA_ERRORCODE (*p_ia_process_api)(pVOID p_ia_process_api_obj,
		WORD32 i_cmd, WORD32 i_idx, pVOID pv_value);

#ifdef MP3_DEC_SET_CONFIG_PARAMS
	/* The set config from argc argv */
	IA_ERRORCODE (*p_set_config_param) (
		WORD32 argc, pWORD8 argv[], pVOID p_ia_process_api_obj);
#endif

	/* The get config from API */
	IA_ERRORCODE (*p_get_config_param) (
		pVOID p_ia_process_api_obj, pWORD32 pi_samp_freq,
		pWORD32 pi_num_chan, pWORD32 pi_pcm_wd_sz);

#ifdef DEBUG_ERROR_HANDLER	
	/* The error init function */
	VOID (*p_error_init)();

	/* The process error info structure */
	ia_error_info_struct *p_proc_err_info;
#endif

 	/* Stack process struct initing */
#ifdef FRDM_K28F	
	p_ia_process_api = ia_mp3_dec_api;	
#endif	
#ifdef MP3_DEC_SET_CONFIG_PARAMS
	p_set_config_param = ia_mp3_dec_set_config_param;
#endif
	p_get_config_param = ia_mp3_dec_get_config_param;
#ifdef DEBUG_ERROR_HANDLER	
	p_error_init = ia_mp3_dec_error_handler_init;
	p_proc_err_info = &ia_mp3_dec_error_info;
#endif

	if (!mp3_decoder_init)
	{
	/* ******************************************************************/
	/* Initialize the error handler                                     */
	/* ******************************************************************/
#ifdef DEBUG_ERROR_HANDLER	
	(*p_error_init)();
#endif
	/* ******************************************************************/
	/* Initialize API structure and set config params to default        */
	/* ******************************************************************/

	/* Get the API size */
	err_code = (*p_ia_process_api)(NULL, IA_API_CMD_GET_API_SIZE, 0,
		&pui_ap_isize);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	/* Allocate memory for API */
	//g_pv_arr_alloc_memory[g_w_malloc_count] = malloc(pui_ap_isize + 4);
	g_pv_arr_alloc_memory[g_w_malloc_count] = &g_pv_array[g_pv_index];
  g_pv_index += pui_ap_isize + 4;

	/* API object requires 4 bytes (WORD32) alignment */
	ui_rem = ((WORD32)g_pv_arr_alloc_memory[g_w_malloc_count] & 3);

	/* Set API object with the memory allocated */
	pv_ia_process_api_obj =
		(pVOID)((WORD8*)g_pv_arr_alloc_memory[g_w_malloc_count] + 4 - ui_rem);

	g_w_malloc_count++;

	/* Set the config params to default values */
	err_code = (*p_ia_process_api)(
		pv_ia_process_api_obj,
		IA_API_CMD_INIT,
		IA_CMD_TYPE_INIT_API_PRE_CONFIG_PARAMS,
		NULL);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	/* ******************************************************************/
	/* Set config parameters got from the user present in argc argv     */
	/* ******************************************************************/

#ifdef MP3_DEC_SET_CONFIG_PARAMS
	err_code = (*p_set_config_param)(argc, argv, pv_ia_process_api_obj);
	_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	/* ******************************************************************/
	/* Initialize Memory info tables                                    */
	/* ******************************************************************/

	/* Get memory info tables size */
	err_code = (*p_ia_process_api)(
		pv_ia_process_api_obj,
		IA_API_CMD_GET_MEMTABS_SIZE, 0,
		&ui_proc_mem_tabs_size);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	//g_pv_arr_alloc_memory[g_w_malloc_count] = malloc(ui_proc_mem_tabs_size + 4);
	g_pv_arr_alloc_memory[g_w_malloc_count] = &g_pv_array[g_pv_index];
  g_pv_index += ui_proc_mem_tabs_size + 4;

	/* API object requires 4 bytes (WORD32) alignment */
	ui_rem = ((WORD32)g_pv_arr_alloc_memory[g_w_malloc_count] & 3);

	/* Set pointer for process memory tables	*/
	err_code = (*p_ia_process_api)(
		pv_ia_process_api_obj,
		IA_API_CMD_SET_MEMTABS_PTR, 0,
		(pVOID)((WORD8*)g_pv_arr_alloc_memory[g_w_malloc_count] + 4 - ui_rem));

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info,(pCHAR8) "", err_code);
#endif

	g_w_malloc_count++;

	/* initialize the API, post config, fill memory tables	*/
	err_code = (*p_ia_process_api)(
		pv_ia_process_api_obj,
		IA_API_CMD_INIT,
		IA_CMD_TYPE_INIT_API_POST_CONFIG_PARAMS,
		NULL);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	/* ******************************************************************/
	/* Allocate Memory with info from library                           */
	/* ******************************************************************/

	/* Get number of memory tables required */
	err_code = (*p_ia_process_api)(
		pv_ia_process_api_obj,
		IA_API_CMD_GET_N_MEMTABS, 0, &n_mems);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info,(pCHAR8) "", err_code);
#endif

	for(i = 0; i < (WORD32)n_mems; i++)
	{
		pVOID pv_alloc_ptr;
		int ui_size,ui_alignment;
		int ui_type;

		/* Get memory size */
		err_code = (*p_ia_process_api)(
			pv_ia_process_api_obj,
			IA_API_CMD_GET_MEM_INFO_SIZE, i,
			&ui_size);

#ifdef DEBUG_ERROR_HANDLER	
		_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

		/* Get memory alignment */
		err_code = (*p_ia_process_api)(
			pv_ia_process_api_obj,
			IA_API_CMD_GET_MEM_INFO_ALIGNMENT, i,
			&ui_alignment);

#ifdef DEBUG_ERROR_HANDLER	
		_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

		/* Get memory type */
		err_code = (*p_ia_process_api)(
			pv_ia_process_api_obj,
			IA_API_CMD_GET_MEM_INFO_TYPE, i,
			&ui_type);

#ifdef DEBUG_ERROR_HANDLER	
		_IA_HANDLE_ERROR(p_proc_err_info,(pCHAR8) "", err_code);
#endif

		if(ui_type == IA_MEMTYPE_INPUT)
		{
			//g_pv_arr_alloc_memory[g_w_malloc_count] = malloc(ui_size + ui_alignment);
			g_pv_arr_alloc_memory[g_w_malloc_count] = in_buf;
		}
		else if (ui_type == IA_MEMTYPE_OUTPUT)
		{
			//g_pv_arr_alloc_memory[g_w_malloc_count] = malloc(ui_size + ui_alignment);
			g_pv_arr_alloc_memory[g_w_malloc_count] = out_buf; 
		}
		else if (ui_type == IA_MEMTYPE_PERSIST)
		{
			//g_pv_arr_alloc_memory[g_w_malloc_count] = malloc(ui_size + ui_alignment);
			g_pv_arr_alloc_memory[g_w_malloc_count] = g_pv_pers_array;
		}
		else if (ui_type == IA_MEMTYPE_SCRATCH)
		{
			//g_pv_arr_alloc_memory[g_w_malloc_count] = malloc(ui_size + ui_alignment);
			g_pv_arr_alloc_memory[g_w_malloc_count] = g_pv_sct_array;
		}		

		ui_rem =
			((WORD32)g_pv_arr_alloc_memory[g_w_malloc_count] % ui_alignment);
		pv_alloc_ptr =
			(pVOID )((WORD8*)g_pv_arr_alloc_memory[g_w_malloc_count] +
			ui_alignment - ui_rem);

		g_w_malloc_count++;
		if(ui_type == IA_MEMTYPE_INPUT)
		{
			pv_alloc_ptr = in_buf;
		}
		else if (ui_type == IA_MEMTYPE_OUTPUT)
		{
			pv_alloc_ptr = out_buf;
		}
		/* Set the buffer pointer */
		err_code = (*p_ia_process_api)(
			pv_ia_process_api_obj,
			IA_API_CMD_SET_MEM_PTR, i,
			pv_alloc_ptr);
		
#ifdef DEBUG_ERROR_HANDLER	
		_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	}
	/* End first part */

	/* Second part        */
	/* Initialize process */
	/* Get config params  */
	/* ******************************************************************/
	/* Initialize process in a loop (to handle junk data at beginning)  */
	/* ******************************************************************/

	{
		/* Initialize the process */
		err_code = (*p_ia_process_api)(
				pv_ia_process_api_obj, IA_API_CMD_INIT,
				IA_CMD_TYPE_INIT_PROCESS, NULL);

#ifdef DEBUG_ERROR_HANDLER	
		_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	}
	/* Init end of process condition end */


	/* ******************************************************************/
	/* Get config params from API                                       */
	/* ******************************************************************/

	err_code = (*p_get_config_param)(pv_ia_process_api_obj,
		&i_samp_freq, &i_num_chan, &i_pcm_wd_sz);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	/* End second part */
	mp3_decoder_init = 1;
	
}
	/* Tell that the input is over in this buffer */
	err_code = (*p_ia_process_api)(
			pv_ia_process_api_obj,
			IA_API_CMD_INPUT_OVER, 0, NULL);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info,(pCHAR8) "", err_code);
#endif

	/* Set number of bytes to be processed */
	err_code = (*p_ia_process_api)(
			pv_ia_process_api_obj,
			IA_API_CMD_SET_INPUT_BYTES, 0, &i_buff_size);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	/* Execute process */
	err_code = (*p_ia_process_api)
		(pv_ia_process_api_obj,
		 IA_API_CMD_EXECUTE,
		 IA_CMD_TYPE_DO_EXECUTE, NULL);

#ifdef DEBUG_ERROR_HANDLER	
  if(err_code != IA_NO_ERROR)
	{
		ia_error_handler(p_proc_err_info, (pCHAR8)"", err_code);
	}
#endif
/*
	if(err_code == 0x00001000)
		need_more_bits = 1;
	else
		need_more_bits = 0;*/

	err_code = (*p_get_config_param)(pv_ia_process_api_obj, 
			&i_samp_freq, &i_num_chan, &i_pcm_wd_sz);

	/* Checking for end of processing */
	err_code = (*p_ia_process_api)(
			pv_ia_process_api_obj,
			IA_API_CMD_EXECUTE,
			IA_CMD_TYPE_DONE_QUERY,
			&ui_exec_done);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	/* Get the output bytes */
	err_code = (*p_ia_process_api)(
			pv_ia_process_api_obj,
			IA_API_CMD_GET_OUTPUT_BYTES, 0,
			&i_out_bytes);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info, (pCHAR8)"", err_code);
#endif

	i_total_bytes += i_out_bytes;

	/* How much buffer is used in input buffers */
	err_code = (*p_ia_process_api)(
			pv_ia_process_api_obj,
			IA_API_CMD_GET_CURIDX_INPUT_BUF, 0,
			&i_bytes_consumed);

#ifdef DEBUG_ERROR_HANDLER	
	_IA_HANDLE_ERROR(p_proc_err_info,(pCHAR8) "", err_code);
#endif

	return IA_NO_ERROR;

}

uint32_t bitrate_lut[] = {0, 32000, 40000, 48000, 56000, 64000, 80000, 96000, 
													112000, 128000, 160000, 192000, 224000, 256000, 320000, 0x0};
uint32_t sample_freq_lut[] = {44100, 48000, 32000, 0};
uint32_t get_mp3_frame_len(uint8_t *mp3_buf)
{
	uint32_t frame_header = 0;
	uint32_t bitrate_idx = 0;
	uint32_t sample_freq_idx = 0;
	uint8_t padding = 0;
	uint32_t frame_len;
	
	frame_header = (mp3_buf[2] << 8) + mp3_buf[3];
	bitrate_idx = (frame_header >> 12) & 0xF;
	sample_freq_idx = (frame_header >> 10) & 0x3;
	padding = (frame_header >> 9) & 0x1;
	frame_len = ((144*bitrate_lut[bitrate_idx])/sample_freq_lut[sample_freq_idx]) + padding;
	return frame_len;
}
#endif