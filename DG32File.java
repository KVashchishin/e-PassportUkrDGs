import net.sf.scuba.smartcards.CardFileInputStream;
import org.bouncycastle.asn1.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Gets registration place from DG32 file (288) in passport (it also contains
 * registration date, you can supplement this code if needed)
 * 
 * Use:
 * 
 * ps - PassportService;
 * 
 * DG32File dg32File = new DG32File(ps.getInputStream(DG32File.DG_FID));
 * 
 * Hint:
 * 
 * If needed you can see file content in ASN1 format:
 * 
 * obj - ASN1Primitive;
 * 
 * ASN1Dump.dumpAsString(obj, true);
 * 
 * @author Philemon
 */
public class DG32File {
    public static final short DG_FID = 288;

    private String registrationPlace;

    public DG32File(CardFileInputStream inputStream) throws IOException {
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

            DEROctetString octetString = (DEROctetString) sequence1.getObjectAt(0);

            setRegistrationPlace(new String(octetString.getOctets()).replace("<", " "));
        }
    }

    public String getRegistrationPlace() {
        return this.registrationPlace;
    }

    public void setRegistrationPlace(String registrationPlace) {
        this.registrationPlace = registrationPlace;
    }
}
