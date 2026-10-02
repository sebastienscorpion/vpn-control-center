from enum import Enum

from pydantic import BaseModel, Field, IPvAnyAddress, IPvAnyNetwork


class IKEVersion(str, Enum):
    IKEV1 = "ikev1"
    IKEV2 = "ikev2"


class AuthenticationMethod(str, Enum):
    PRE_SHARED_KEY = "pre-shared-key"
    CERTIFICATE = "certificate"


class TunnelMode(str, Enum):
    TUNNEL = "tunnel"
    TRANSPORT = "transport"


class DPDAction(str, Enum):
    RESTART = "restart"
    CLEAR = "clear"
    HOLD = "hold"


class EncryptionAlgorithm(str, Enum):
    AES128 = "aes128"
    AES192 = "aes192"
    AES256 = "aes256"
    AES128GCM16 = "aes128gcm16"
    AES256GCM16 = "aes256gcm16"
    CHACHA20POLY1305 = "chacha20poly1305"


class IntegrityAlgorithm(str, Enum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class DHGroup(str, Enum):
    MODP768 = "modp768"
    MODP1024 = "modp1024"
    MODP1536 = "modp1536"
    MODP2048 = "modp2048"
    MODP3072 = "modp3072"
    MODP4096 = "modp4096"
    MODP6144 = "modp6144"
    MODP8192 = "modp8192"
    ECP256 = "ecp256"
    ECP384 = "ecp384"
    ECP521 = "ecp521"


class IKEProposal(BaseModel):
    encryption: EncryptionAlgorithm
    integrity: IntegrityAlgorithm
    dh_group: DHGroup

    def to_strongswan(self):
        return (
            f"{self.encryption.value}-"
            f"{self.integrity.value}-"
            f"{self.dh_group.value}"
        )


class ESPProposal(BaseModel):
    encryption: EncryptionAlgorithm
    integrity: IntegrityAlgorithm | None = None
    dh_group: DHGroup | None = None

    def to_strongswan(self):
        value = self.encryption.value

        if self.integrity:
            value += f"-{self.integrity.value}"

        if self.dh_group:
            value += f"-{self.dh_group.value}"

        return value


class IPsecTunnel(BaseModel):
    name: str

    # Gateway
    local_gateway: IPvAnyAddress
    remote_gateway: IPvAnyAddress

    # Authentication
    authentication: AuthenticationMethod
    pre_shared_key: str | None = None

    # IKE
    ike_version: IKEVersion
    ike_proposals: list[IKEProposal]

    ike_lifetime: int = Field(
        default=86400,
        ge=60,
    )

    # Phase 2
    esp_proposals: list[ESPProposal]

    ipsec_lifetime: int = Field(
        default=28800,
        ge=60,
    )

    # Selectors
    local_subnets: list[IPvAnyNetwork]
    remote_subnets: list[IPvAnyNetwork]

    # DPD
    dpd_enabled: bool = True
    dpd_interval: int = 30
    dpd_timeout: int = 120
    dpd_action: DPDAction = DPDAction.RESTART

    # Rekey
    rekey: bool = False

    # Mode
    mode: TunnelMode = TunnelMode.TUNNEL