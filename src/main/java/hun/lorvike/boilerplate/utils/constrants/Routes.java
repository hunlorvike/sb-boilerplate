package hun.lorvike.boilerplate.utils.constrants;

public class Routes {
    public static final String API_ROOT = "/api";
    public static final String AUTH = API_ROOT + "/auth";
    public static final String AGENCY = API_ROOT + "/agencies";
    public static final String TEST = "/admin/test";

    private Routes() {
        throw new IllegalStateException("Utility class");
    }
}
