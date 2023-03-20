/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#pragma once

typedef struct
{
	LIST_ENTRY	PipeList;
	HANDLE		Pipe;
} PIPE_ENTRY_BEACON, *PPIPE_ENTRY_BEACON ;
