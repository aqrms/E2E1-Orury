package com.kernel360.orury.domain.user.model;

import com.kernel360.orury.global.common.Api;
import com.kernel360.orury.global.common.ApiStatus;

public record ApiResponse(
	ApiStatus status,
	String message,
	Object data
) {
	public static ApiResponse success(Object data) {
		return new ApiResponse(ApiStatus.SUCCESS, null, data);
	}

	public static ApiResponse error(String message) {
		return new ApiResponse(ApiStatus.ERROR, message, null);
	}
}