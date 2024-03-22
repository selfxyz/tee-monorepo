// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IAttestationVerifier.sol";

contract AttestationVerifier is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    UUPSUpgradeable, // public upgrade
    IAttestationVerifier // interface
{
    // in case we add more contracts in the inheritance chain
    uint256[500] private __gap_0;

    /// @custom:oz-upgrades-unsafe-allow constructor
    // disable all initializers and reinitializers
    // safeguard against takeover of the logic contract
    constructor() {
        _disableInitializers();
    }

    //-------------------------------- Overrides start --------------------------------//

    error AttestationVerifierCannotRemoveAllAdmins();

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165Upgradeable, AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    error AttestationVerifierNoImageProvided();
    error AttestationVerifierInitLengthMismatch();
    error AttestationVerifierInvalidAdmin();

    function initialize(EnclaveImage[] memory images, bytes[] memory enclaveKeys, address _admin) external initializer {
        // The images and their enclave keys are whitelisted without verification that enclave keys are created within
        // the enclave. This is to initialize chain of trust and will be replaced with a more robust solution.
        if (!(images.length != 0)) revert AttestationVerifierNoImageProvided();
        if (!(images.length == enclaveKeys.length)) revert AttestationVerifierInitLengthMismatch();
        if (!(_admin != address(0))) revert AttestationVerifierInvalidAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        for (uint i = 0; i < enclaveKeys.length; i++) {
            bytes32 imageId = _whitelistEnclaveImage(images[i]);
            _whitelistEnclaveKey(enclaveKeys[i], imageId);
        }
    }

    //-------------------------------- Initializer start --------------------------------//

    //-------------------------------- Declarations start --------------------------------//

    struct EnclaveImage {
        bytes PCR0;
        bytes PCR1;
        bytes PCR2;
    }

    // ImageId -> image details
    mapping(bytes32 => EnclaveImage) public whitelistedImages;
    // enclaveKey -> ImageId
    mapping(address => bytes32) public isVerified;

    uint256[48] private __gap_1;

    //-------------------------------- Declarations end --------------------------------//

    //-------------------------------- Admin methods start --------------------------------//

    error AttestationVerifierPubkeyLengthInvalid();
    error AttestationVerifierPCRsInvalid();

    error AttestationVerifierImageNotWhitelisted();
    error AttestationVerifierImageAlreadyWhitelisted();
    error AttestationVerifierKeyNotVerified();
    error AttestationVerifierKeyAlreadyVerified();

    event EnclaveImageWhitelisted(bytes32 indexed imageId, bytes PCR0, bytes PCR1, bytes PCR2);
    event EnclaveImageRevoked(bytes32 indexed imageId);
    event EnclaveKeyWhitelisted(bytes indexed enclavePubKey, bytes32 indexed imageId);
    event EnclaveKeyRevoked(bytes indexed enclavePubKey);
    event EnclaveKeyVerified(bytes indexed enclavePubKey, bytes32 indexed imageId);

    function _pubKeyToAddress(bytes memory pubKey) internal pure returns (address) {
        if (!(pubKey.length == 64)) revert AttestationVerifierPubkeyLengthInvalid();

        bytes32 hash = keccak256(pubKey);
        return address(uint160(uint256(hash)));
    }

    function pubKeyToAddress(bytes memory pubKey) public pure returns (address) {
        return _pubKeyToAddress(pubKey);
    }

    function _whitelistEnclaveImage(EnclaveImage memory image) internal returns (bytes32) {
        if (!(image.PCR0.length == 48 && image.PCR1.length == 48 && image.PCR2.length == 48))
            revert AttestationVerifierPCRsInvalid();

        bytes32 imageId = keccak256(abi.encodePacked(image.PCR0, image.PCR1, image.PCR2));
        if (!(whitelistedImages[imageId].PCR0.length == 0)) revert AttestationVerifierImageAlreadyWhitelisted();
        whitelistedImages[imageId] = EnclaveImage(image.PCR0, image.PCR1, image.PCR2);
        emit EnclaveImageWhitelisted(imageId, image.PCR0, image.PCR1, image.PCR2);
        return imageId;
    }

    function _revokeEnclaveImage(bytes32 imageId) internal {
        if (!(whitelistedImages[imageId].PCR0.length != 0)) revert AttestationVerifierImageNotWhitelisted();
        delete whitelistedImages[imageId];
        emit EnclaveImageRevoked(imageId);
    }

    function _whitelistEnclaveKey(bytes memory enclavePubKey, bytes32 imageId) internal {
        if (!(whitelistedImages[imageId].PCR0.length != 0)) revert AttestationVerifierImageNotWhitelisted();
        address enclaveKey = _pubKeyToAddress(enclavePubKey);
        if (!(isVerified[enclaveKey] == bytes32(0))) revert AttestationVerifierKeyAlreadyVerified();
        isVerified[enclaveKey] = imageId;
        emit EnclaveKeyWhitelisted(enclavePubKey, imageId);
    }

    function _revokeEnclaveKey(bytes memory enclavePubKey) internal {
        address enclaveKey = _pubKeyToAddress(enclavePubKey);
        if (!(isVerified[enclaveKey] != bytes32(0))) revert AttestationVerifierKeyNotVerified();
        delete isVerified[enclaveKey];
        emit EnclaveKeyRevoked(enclavePubKey);
    }

    function whitelistEnclaveImage(
        bytes memory PCR0,
        bytes memory PCR1,
        bytes memory PCR2
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _whitelistEnclaveImage(EnclaveImage(PCR0, PCR1, PCR2));
    }

    function revokeEnclaveImage(bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        return _revokeEnclaveImage(imageId);
    }

    function whitelistEnclaveKey(bytes memory enclavePubKey, bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        return _whitelistEnclaveKey(enclavePubKey, imageId);
    }

    function revokeEnclaveKey(bytes memory enclavePubKey) external onlyRole(DEFAULT_ADMIN_ROLE) {
        return _revokeEnclaveKey(enclavePubKey);
    }

    //-------------------------------- Admin methods end --------------------------------//

    //-------------------------------- Open methods start -------------------------------//

    uint256 public constant MAX_AGE = 300;

    error AttestationVerifierAttestationTooOld();

    function _verifyEnclaveKey(
        bytes memory signature,
        bytes memory enclavePubKey,
        bytes32 imageId,
        uint256 timestampInMilliseconds
    ) internal {
        if (!(timestampInMilliseconds / 1000 > block.timestamp - MAX_AGE))
            revert AttestationVerifierAttestationTooOld();
        if (!(whitelistedImages[imageId].PCR0.length != 0)) revert AttestationVerifierImageNotWhitelisted();

        address enclaveKey = pubKeyToAddress(enclavePubKey);
        if (!(isVerified[enclaveKey] == bytes32(0))) revert AttestationVerifierKeyAlreadyVerified();

        EnclaveImage memory image = whitelistedImages[imageId];
        _verify(signature, enclavePubKey, image, timestampInMilliseconds);

        isVerified[enclaveKey] = imageId;
        emit EnclaveKeyVerified(enclavePubKey, imageId);
    }

    function verifyEnclaveKey(
        bytes memory signature,
        bytes memory enclavePubKey,
        bytes32 imageId,
        uint256 timestampInMilliseconds
    ) external {
        return
            _verifyEnclaveKey(signature, enclavePubKey, imageId, timestampInMilliseconds);
    }

    //-------------------------------- Open methods end -------------------------------//

    //-------------------------------- Read only methods start -------------------------------//

    error AttestationVerifierDoesNotVerify();

    bytes32 private constant DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version)"),
                keccak256("marlin.oyster.AttestationVerifier"),
                keccak256("1")
            )
        );

    struct Attestation {
        bytes enclaveKey;
        bytes PCR0;
        bytes PCR1;
        bytes PCR2;
        uint256 timestamp;
    }
    bytes32 private constant ATTESTATION_TYPEHASH =
        keccak256("Attestation(bytes enclaveKey,bytes PCR0,bytes PCR1,bytes PCR2,uint256 timestamp)");

    function _verify(
        bytes memory signature,
        bytes memory enclaveKey,
        EnclaveImage memory image,
        uint256 timestamp
    ) internal view {
        bytes32 hashStruct = keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
                keccak256(enclaveKey),
                keccak256(image.PCR0),
                keccak256(image.PCR1),
                keccak256(image.PCR2),
                timestamp
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hashStruct));

        address signer = ECDSA.recover(digest, signature);
        bytes32 sourceImageId = isVerified[signer];

        if (!(sourceImageId != bytes32(0) && whitelistedImages[sourceImageId].PCR0.length != 0))
            revert AttestationVerifierDoesNotVerify();
    }

    function verify(
        bytes memory signature,
        bytes memory enclaveKey,
        bytes memory PCR0,
        bytes memory PCR1,
        bytes memory PCR2,
        uint256 timestamp
    ) external view {
        _verify(signature, enclaveKey, EnclaveImage(PCR0, PCR1, PCR2), timestamp);
    }

    function verify(bytes memory data) external view {
        (
            bytes memory signature,
            bytes memory enclaveKey,
            bytes memory PCR0,
            bytes memory PCR1,
            bytes memory PCR2,
            uint256 enclaveCPUs,
            uint256 enclaveMemory,
            uint256 timestamp
        ) = abi.decode(data, (bytes, bytes, bytes, bytes, bytes, uint256, uint256, uint256));
        _verify(signature, enclaveKey, EnclaveImage(PCR0, PCR1, PCR2), timestamp);
    }

    //-------------------------------- Read only methods end -------------------------------//
}
