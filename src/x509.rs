use std::str;
use std::fmt;
use std::convert::From;

use nom::IResult;
use num::bigint::BigUint;
use time::{strptime,Tm};

use der_parser::*;
use der_parser::oid::Oid;
use objects::*;
use error::X509Error;
use x509_parser::parse_ext_basicconstraints;


#[derive(Debug)]
pub struct X509Extension<'a> {
    pub oid:  Oid,
    pub critical: bool,
    pub value: &'a[u8],
}

#[derive(Debug)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm:  Oid,
    pub parameters: DerObject<'a>,
}

impl<'a> AlgorithmIdentifier<'a> {
    pub fn from_der_object(mut o: DerObject<'a>) -> Result<AlgorithmIdentifier<'a>,X509Error> {
        match o.content {
            DerObjectContent::Sequence(ref mut v) => {
                let obj_param = v.pop().ok_or(X509Error::InvalidAlgorithmIdentifier)?;
                let obj_alg   = v.pop().ok_or(X509Error::InvalidAlgorithmIdentifier)?;
                if let DerObjectContent::OID(ref oid) = obj_alg.content {
                    Ok(AlgorithmIdentifier{
                        algorithm:  oid.clone(),
                        parameters: obj_param,
                    })
                } else {
                    Err(X509Error::InvalidAlgorithmIdentifier)
                }
            },
            _ => Err(X509Error::InvalidAlgorithmIdentifier),
        }
    }
}

#[derive(Debug)]
pub struct X509Name<'a> {
    pub obj: DerObject<'a>,
}

impl<'a> X509Name<'a> {
    pub fn from_der_object(o: DerObject<'a>) -> Result<X509Name<'a>,X509Error> {
        Ok(X509Name{ obj: o })
    }
}

impl<'a> fmt::Display for X509Name<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match x509name_to_string(&self.obj) {
            Ok(o)  => write!(f, "{}", o),
            Err(_) => write!(f, "<X509Error: Invalid X.509 name>"),
        }
    }
}



/// From RF5280:
///
///   TBSCertificate  ::=  SEQUENCE  {
///        version         [0]  EXPLICIT Version DEFAULT v1,
///        serialNumber         CertificateSerialNumber,
///        signature            AlgorithmIdentifier,
///        issuer               Name,
///        validity             Validity,
///        subject              Name,
///        subjectPublicKeyInfo SubjectPublicKeyInfo,
///        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                             -- If present, version MUST be v2 or v3
///        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                             -- If present, version MUST be v2 or v3
///        extensions      [3]  EXPLICIT Extensions OPTIONAL
///                             -- If present, version MUST be v3
///        }
#[derive(Debug)]
pub struct TbsCertificate<'a> {
    version: DerObject<'a>,
    serial: DerObject<'a>,
    signature: DerObject<'a>,
    issuer: X509Name<'a>,
    validity: DerObject<'a>,
    subject: X509Name<'a>,
    subject_pki: DerObject<'a>,
    issuer_uid: DerObject<'a>,
    subject_uid: DerObject<'a>,
    extensions: Vec<X509Extension<'a>>,
}

/// Internal function
/// Create the vector of extensions from the DER sequence
/// Consumes the input value
fn extract_extensions<'a>(o: &mut DerObject<'a>) -> Result<Vec<X509Extension<'a>>,X509Error> {
    let mut extensions = Vec::new();
    let mut cs = o.as_context_specific()?;
    if let Some(ref mut obj_seq) = cs.1 {
        if let DerObjectContent::Sequence(ref mut v) = obj_seq.content {
            while let Some(mut ext) = v.pop() {
                let v_ext = match ext.content {
                    DerObjectContent::Sequence(ref mut x) => x,
                    _ => return Err(X509Error::InvalidExtensions),
                };
                let obj_val = v_ext.pop().ok_or(X509Error::InvalidExtensions)?;
                let obj_cri = v_ext.pop().ok_or(X509Error::InvalidExtensions)?;
                let obj_oid = v_ext.pop().ok_or(X509Error::InvalidExtensions)?;
                let oid = obj_oid.as_oid()?;
                let crit_obj = obj_cri.as_context_specific()?;
                let crit = match crit_obj.1 {
                    Some(co) => co.as_bool()?,
                    None     => false, // default critical value
                };
                let val = obj_val.as_slice()?;
                extensions.push(X509Extension{
                    oid:      oid.clone(),
                    critical: crit,
                    value:    val,
                });
            }
            return Ok(extensions);
        }
    }
    Err(X509Error::InvalidExtensions)
}

impl<'a> TbsCertificate<'a> {
    pub fn from_der_object(mut o: DerObject<'a>) -> Result<TbsCertificate<'a>,X509Error> {
        match o.content {
            DerObjectContent::Sequence(ref mut v) => {
                let mut obj_ext = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let obj_subject_id = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let obj_issuer_id = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let obj_subj_pki = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let obj_subject = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let obj_validity = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let obj_issuer = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let obj_signature = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let obj_serial = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let obj_version = v.pop().ok_or(X509Error::InvalidTbsCertificate)?;
                let extensions = extract_extensions(&mut obj_ext)?;
                Ok(TbsCertificate{
                    version: obj_version,
                    serial: obj_serial,
                    signature: obj_signature,
                    issuer: X509Name::from_der_object(obj_issuer)?,
                    validity: obj_validity,
                    subject: X509Name::from_der_object(obj_subject)?,
                    subject_pki: obj_subj_pki,
                    issuer_uid: obj_issuer_id,
                    subject_uid: obj_subject_id,
                    extensions: extensions,
                })
            },
            _ => Err(X509Error::Generic),
        }
    }

    /// Get the certificate version
    ///
    /// From RFC5280:
    /// version         [0]  EXPLICIT Version DEFAULT v1,
    ///
    /// and Version is defined as:
    ///
    /// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
    pub fn version(&self) -> Result<u8,X509Error>
    {
        match self.version.content {
            DerObjectContent::ContextSpecific(0,Some(ref cs)) => {
                if let DerObjectContent::Integer(ref i) = cs.content {
                    if i.len() == 1 && i[0] < 3 {
                        return Ok(i[0]);
                    }
                }
                return Err(X509Error::InvalidVersion);
            },
            DerObjectContent::ContextSpecific(0,None) => {
                // Version is absent, use default (v1)
                return Ok(0);
            }
            _ => Err(X509Error::InvalidVersion),
        }
    }

    pub fn serial(&self) -> Result<BigUint,X509Error> {
        match self.serial.as_biguint() {
            Some(ui) => Ok(ui),
            None     => Err(X509Error::InvalidSerial),
        }
    }

    pub fn signature(&self) -> Result<AlgorithmIdentifier,X509Error> {
        AlgorithmIdentifier::from_der_object(self.signature.clone())
    }

    pub fn issuer(&self) -> &X509Name {
        &self.issuer
    }

    /// RFC5280 section 4.1.2.5
    ///
    ///Both notBefore and notAfter may be encoded as UTCTime or GeneralizedTime.
    ///
    /// To indicate that a certificate has no well-defined expiration date,
    /// the notAfter SHOULD be assigned the GeneralizedTime value of
    /// 99991231235959Z.
    pub fn validity(&self) -> Result<Vec<Tm>,X509Error> {
        let v = self.validity.as_sequence()?;
        let r : Vec<_> = v.iter().fold(
            Ok(Vec::new()),
            |acc,x| {
                if let Ok(mut a) = acc {
                    if let DerObjectContent::UTCTime(s) = x.content {
                        let xs = str::from_utf8(s).or(Err(X509Error::InvalidDate))?;
                        match strptime(xs,"%y%m%d%H%M%S%Z") {
                            Ok(mut tm) => {
                                if tm.tm_year < 50 { tm.tm_year += 100; }
                                // eprintln!("date: {}", tm.rfc822());
                                a.push(tm);
                                Ok(a)
                            },
                            Err(_e) => {
                                // eprintln!("Error: {:?}",_e);
                                Err(X509Error::InvalidDate)
                            },
                        }
                    } else {
                        Err(X509Error::InvalidDate)
                    }
                } else {
                    acc
                }
            })?;
        Ok(r)
    }

    pub fn validity_raw(&self) -> Result<&DerObject,X509Error> {
        Ok(&self.validity)
    }

    pub fn subject(&self) -> &X509Name {
        &self.subject
    }

    pub fn subject_public_key_info(&self) -> &DerObject {
        &self.subject_pki
    }

    pub fn issuer_unique_id(&self) -> &DerObject {
        &self.issuer_uid
    }

    pub fn subject_unique_id(&self) -> &DerObject {
        &self.subject_uid
    }

    /// Get the list of extensions, in order of appearance in the certificate.
    ///
    /// Extensions are stored uninterpreted
    pub fn extensions(&self) -> &Vec<X509Extension<'a>> {
        &self.extensions
    }

    /// Returns true if certificate has `basicConstraints CA:true`
    ///
    ///   id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
    ///   BasicConstraints ::= SEQUENCE {
    ///        cA                      BOOLEAN DEFAULT FALSE,
    ///        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
    pub fn is_ca(&self) -> bool {
        // filter on ext: OId(basicConstraints)
        self.extensions.iter().find(|ext| {
            ext.oid == Oid::from(&[2, 5, 29, 19])
        }).and_then(|ext| {
            // parse DER sequence
            if let IResult::Done(_,seq) = parse_ext_basicconstraints(ext.value) {
                // we parsed a sequence, so we know there is one, non-empty
                let seq = seq.as_sequence().unwrap();
                // if seq.len() == 0 { return None; }
                if let Ok(b) = seq[0].as_bool() { Some(b) } else { None }
            } else {
                None
            }
        }).unwrap_or(false)
    }
}


/// Convert a DER representation of a X.509 name to a human-readble string
///
/// RDNs are separated with ","
/// Multiple RDNs are separated with "+"
fn x509name_to_string(obj: &DerObject) -> Result<String,X509Error> {
    obj.ref_iter().fold(
        Ok(String::new()),
        |acc, o| {
            acc.and_then(|mut _vec| {
                o.ref_iter().fold(
                    Ok(String::new()),
                    |acc2, p| {
                        acc2.and_then(|mut _vec2| {
                            if let DerObjectContent::Sequence(ref v) = p.content {
                                if v.len() != 2 { return Err(X509Error::InvalidX509Name); }
                                let attr  = &v[0].content;
                                let value = &v[1];
                                match (attr, value.as_slice()) {
                                    (&DerObjectContent::OID(ref oid),Ok(s)) => {
                                        // println!("object: *** {:?} {:?}", oid, str::from_utf8(s));
                                        let sn_res = oid2nid(oid).and_then(nid2sn);
                                        let sn_str = match sn_res {
                                            Ok(s) => String::from(s),
                                            _     => format!("{:?}",oid),
                                        };
                                        let val_str = String::from_utf8_lossy(s);
                                        let rdn = format!("{}={}", sn_str, val_str);
                                        match _vec2.len() {
                                            0 => Ok(rdn),
                                            _ => Ok(_vec2 + " + " + &rdn),
                                        }
                                    },
                                    _ => { Err(X509Error::InvalidX509Name) },
                                }
                            } else {
                                Err(X509Error::InvalidX509Name)
                            }
                        })
            }).and_then(|v| {
                match _vec.len() {
                    0 => Ok(v),
                    _ => Ok(_vec + ", " + &v),
                }
            })
        })
    })
}


#[derive(Debug)]
pub struct X509Certificate<'a> {
    tbs_certificate: DerObject<'a>,
    signature_algorithm: DerObject<'a>,
    signature_value: &'a[u8],
}

impl<'a> X509Certificate<'a> {
    pub fn from_der_object(mut v: Vec<DerObject>) -> Result<X509Certificate,X509Error> {
        // note, reverse order
        let obj_sig = v.pop().ok_or(X509Error::InvalidCertificate)?;
        let obj_alg = v.pop().ok_or(X509Error::InvalidCertificate)?;
        let obj_crt = v.pop().ok_or(X509Error::InvalidCertificate)?;
        let slice = obj_sig.as_slice()?;
        Ok(X509Certificate{
            tbs_certificate:     obj_crt,
            signature_algorithm: obj_alg,
            signature_value:     slice,
        })
    }

    pub fn tbs_certificate(&self) -> Result<TbsCertificate,X509Error> {
        TbsCertificate::from_der_object(self.tbs_certificate.clone())
    }

    pub fn signature_algorithm(&self) -> Result<AlgorithmIdentifier,X509Error> {
        AlgorithmIdentifier::from_der_object(self.signature_algorithm.clone())
    }

    pub fn signature_value(&self) -> Result<&'a[u8],X509Error> {
        Ok(self.signature_value)
    }
}






#[cfg(test)]
mod tests {
    //use super::*;
    //use der::*;
    use x509::X509Name;
    use der_parser::*;
    use der_parser::oid::Oid;

#[test]
fn test_x509_name() {
    let obj = DerObject::from_obj(
        DerObjectContent::Sequence(
            vec![
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 6]))), // countryName
                        DerObject::from_obj(DerObjectContent::PrintableString(b"FR")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 8]))), // stateOrProvinceName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Some-State")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 10]))), // organizationName
                        DerObject::from_obj(DerObjectContent::UTF8String(b"Internet Widgits Pty Ltd")),
                    ])),
                ])),
                DerObject::from_obj(DerObjectContent::Set(vec![
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 3]))), // CN
                        DerObject::from_obj(DerObjectContent::PrintableString(b"Test1")),
                    ])),
                    DerObject::from_obj(DerObjectContent::Sequence(vec![
                        DerObject::from_obj(DerObjectContent::OID(Oid::from(&[2, 5, 4, 3]))), // CN
                        DerObject::from_obj(DerObjectContent::PrintableString(b"Test2")),
                    ])),
                ])),
            ]
        )
    );
    let name = X509Name::from_der_object(obj).unwrap();
    assert_eq!(name.to_string(), "C=FR, ST=Some-State, O=Internet Widgits Pty Ltd, CN=Test1 + CN=Test2");
}

}
