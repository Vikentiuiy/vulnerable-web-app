import java.util.regex.*;
public class ReTest {
  public static void main(String[] a){
    Pattern p = Pattern.compile("^(a+)+$");
    for(int n : new int[]{20,25,28,30,32,34}){
      String s = "a".repeat(n) + "!";
      long t0=System.currentTimeMillis();
      boolean m = p.matcher(s).matches();
      long dt=System.currentTimeMillis()-t0;
      System.out.println("n="+n+" ms="+dt+" match="+m);
      if(dt>5000){System.out.println("(stopping, too slow)");break;}
    }
  }
}
