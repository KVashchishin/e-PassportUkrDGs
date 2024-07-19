import net.sf.scuba.smartcards.CardFileInputStream;
import org.bouncycastle.asn1.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Gets IPN(RNTRC) from DG34 file (290) in passport
 * 
 * Use:
 * 
 * ps - PassportService
 * 
 * DG34File dg32File = new DG34File(ps.getInputStream(DG34File.DG_FID));
 * 
 * Hint:
 * 
 * If needed you can see file content in ASN1 format:
 * 
 * obj - ASN1Primitive
 * 
 * ASN1Dump.dumpAsString(obj, true);
 * 
 * @author Philemon
 */
public class DG34File {
    public static final short DG_FID = 290;

    private String ipn = "";

    public DG34File(CardFileInputStream inputStream) throws IOException {
        readContent(inputStream);
    }

    protected void readContent(CardFileInputStream inputStream) throws IOException {
        byte[] sendReadBinary = new byte[inputStream.getLength()];
        inputStream.read(sendReadBinary);
        if (sendReadBinary.length > 0) {
            ASN1InputStream bIn = new ASN1InputStream(new ByteArrayInputStream(sendReadBinary));
            ASN1Primitive obj = bIn.readObject();

            DLTaggedObject application = (DLTaggedObject) obj;

            DLSequence mainSequence = (DLSequence) application.getBaseObject();

            DLSequence sequence1 = (DLSequence) mainSequence.getObjectAt(0);

            DLTaggedObject element = (DLTaggedObject) sequence1.getObjectAt(0);

            DEROctetString octetString = (DEROctetString) element.getBaseObject();

            String ipn = new String(octetString.getOctets());

            this.setIpn(ipn);
        }
    }

    public String getIpn() {
        return this.ipn;
    }

    public void setIpn(String ipn) {
        this.ipn = ipn;
    }
}
