import * as graphene from 'graphene-pk11';
import * as x509 from '@peculiar/x509';
export interface PivTokenAttestation {
  certificate: x509.X509Certificate;
  id: string;
  label: string;
}

export interface SlotInfo {
  slotDescription: string;
  tokenLabel: string;
  tokenSerialNumber: string;
  availableAttestations: PivTokenAttestation[];
  caCertificate?: x509.X509Certificate;
}

export class PivTokenManager {
  private module: graphene.Module;
  private slots: graphene.SlotCollection;

  constructor(tokenPath: string) {
    this.module = graphene.Module.load(tokenPath, 'Yubico PIV');
    this.module.initialize();
    this.slots = this.module.getSlots(true);
  }

  public close() {
    this.module.finalize();
    this.module.close();
  }

  public getSlots(): SlotInfo[] {
    const slots: SlotInfo[] = [];
    for (const slot of this.slots) {
      const slotInfo = this.getSlotInfo(slot);
      slots.push(slotInfo);
    }
    return slots;
  }

  public getSlot(slotIndex: number): SlotInfo | null {
    if (slotIndex < 0 || slotIndex >= this.slots.length) {
      return null;
    }
    const slot = this.slots.items(slotIndex);
    return this.getSlotInfo(slot);
  }

  private getSlotInfo(slot: graphene.Slot): SlotInfo {
    const token = slot.getToken();
    const availableAttestations: PivTokenAttestation[] = [];
    let caCertificate: x509.X509Certificate | undefined;

    const session = slot.open();

    try {
      const objects = session.find({
        class: graphene.ObjectClass.CERTIFICATE,
      });
      for (const obj of objects) {
        const certObj = obj.toType<graphene.X509Certificate>();

        if (
          /^X\.509 Certificate for PIV Attestation [0-9a-f]{2}$/.test(
            certObj.label,
          )
        ) {
          const cert = new x509.X509Certificate(certObj.value);
          availableAttestations.push({
            certificate: cert,
            id: certObj.id.toString('hex'),
            label: certObj.label,
          });
        } else if (certObj.label === 'X.509 Certificate for PIV Attestation') {
          caCertificate = new x509.X509Certificate(certObj.value);
        }
      }

      return {
        slotDescription: slot.slotDescription,
        tokenLabel: token.label,
        tokenSerialNumber: token.serialNumber,
        availableAttestations,
        caCertificate,
      };
    } finally {
      session.close();
    }
  }
}
