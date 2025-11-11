package co.enyoi.authentication.controller;

import co.enyoi.authentication.dto.ApiSuccessResponse;
import co.enyoi.authentication.dto.CreateUserRequest;
import co.enyoi.authentication.dto.UserResponse;
import co.enyoi.authentication.service.UserService;
import co.enyoi.authentication.util.RequestIdUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiSuccessResponse<UserResponse>> createUser(
            @Valid @RequestBody CreateUserRequest request,
            HttpServletRequest httpRequest) {

        String requestId = RequestIdUtil.getRequestId(httpRequest);
        logger.info("[{}] Create user request for username: {}", requestId, request.username());

        UserResponse userResponse = userService.createUser(request);

        ApiSuccessResponse<UserResponse> response = new ApiSuccessResponse<>(
                HttpStatus.CREATED.value(),
                userResponse,
                requestId
        );

        logger.info("[{}] User created successfully: {}", requestId, userResponse.username());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
