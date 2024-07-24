import XML from "../xml";

export default class PatchedXML extends XML {
  static removeGeolocation(xmljs: any) {
    super.removeGeolocation(xmljs);

    xmljs.signers?.[0]?.signer?.forEach(function (signer) {
      if (!signer.auditTrail) {
        signer.event?.forEach(function (event, index) {
          if (event.$.name === "geolocation") {
            delete signer.event[index];
          }
        });
      }
    });
  }
}
