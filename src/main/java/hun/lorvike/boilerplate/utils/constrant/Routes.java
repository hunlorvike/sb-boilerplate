package hun.lorvike.boilerplate.utils.constrant;

public class Routes {
    public static final String API_ROOT = "/api";

    public static final String AUTH = API_ROOT + "/auth";
    public static final String REGISTER = AUTH + "/register";
    public static final String LOGIN = AUTH + "/login";
    public static final String REFRESH_TOKEN = AUTH + "/refresh-token";
    public static final String ME = AUTH + "/me";

    public static final String TEST = API_ROOT + "/test";

    public static final String ROLE = "/role";
    public static final String ROLE_USER = TEST + ROLE + "/user";
    public static final String ROLE_MANAGER = TEST + ROLE + "/manager";
    public static final String ROLE_ADMIN = TEST + ROLE + "/admin";
}
