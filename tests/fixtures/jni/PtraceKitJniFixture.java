import java.util.Arrays;

public final class PtraceKitJniFixture {
    private static native void hold(String value, String empty, String longValue, String malformed);

    public static void main(String[] args) {
        System.load(args[0]);

        char[] prefix = new char[2047];

        Arrays.fill(prefix, 'x');
        hold("初始\u0000🙂", "", new String(prefix) + "🙂tail", new String(new char[] { (char) 0xd800 }));
        System.out.println("JNI_FIXTURE_FINISHED");
    }
}
