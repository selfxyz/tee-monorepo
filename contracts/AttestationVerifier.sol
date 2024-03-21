// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./interfaces/IAttestationVerifier.sol";

contract AttestationVerifier is
    Initializable, // initializer
    ContextUpgradeable, // _msgSender, _msgData
    ERC165Upgradeable, // supportsInterface
    AccessControlUpgradeable, // RBAC
    AccessControlEnumerableUpgradeable, // RBAC enumeration
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
    )
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlUpgradeable, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _grantRole(
        bytes32 role,
        address account
    ) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        return super._grantRole(role, account);
    }

    function _revokeRole(
        bytes32 role,
        address account
    ) internal virtual override(AccessControlUpgradeable, AccessControlEnumerableUpgradeable) returns (bool) {
        bool res = super._revokeRole(role, account);

        // protect against accidentally removing all admins
        if (!(getRoleMemberCount(DEFAULT_ADMIN_ROLE) != 0)) revert AttestationVerifierCannotRemoveAllAdmins();

        return res;
    }

    function _authorizeUpgrade(address /*account*/) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    //-------------------------------- Overrides end --------------------------------//

    //-------------------------------- Initializer start --------------------------------//

    error AttestationVerifierNoImageProvided();
    error AttestationVerifierInitLengthMismatch();
    error AttestationVerifierInvalidAdmin();

    function initialize(
        EnclaveImage[] memory images,
        address[] memory enclaveKeys,
        address _admin
    ) external initializer {
        // The images and their enclave keys are whitelisted without verification that enclave keys are created within
        // the enclave. This is to initialize chain of trust and will be replaced with a more robust solution.
        if (!(images.length != 0)) revert AttestationVerifierNoImageProvided();
        if (!(images.length == enclaveKeys.length)) revert AttestationVerifierInitLengthMismatch();
        if (!(_admin != address(0))) revert AttestationVerifierInvalidAdmin();

        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __UUPSUpgradeable_init_unchained();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        for (uint i = 0; i < enclaveKeys.length; i++) {
            address enclaveKey = enclaveKeys[i];
            bytes32 imageId = _whitelistImage(images[i]);

            isVerified[enclaveKey] = imageId;
            emit EnclaveKeyWhitelisted(imageId, enclaveKey);
        }
    }

    //-------------------------------- Initializer start --------------------------------//

    //-------------------------------- Declarations start --------------------------------//

    struct EnclaveImage {
        bytes PCR0;
        bytes PCR1;
        bytes PCR2;
    }
    string public constant ATTESTATION_PREFIX = "Enclave Attestation Verified";

    // ImageId -> image details
    mapping(bytes32 => EnclaveImage) public whitelistedImages;
    // enclaveKey -> ImageId
    mapping(address => bytes32) public isVerified;

    uint256[48] private __gap_1;

    event EnclaveImageWhitelisted(bytes32 indexed imageId, bytes PCR0, bytes PCR1, bytes PCR2);
    event WhitelistedImageRevoked(bytes32 indexed imageId);
    event WhitelistedEnclaveKeyRevoked(bytes32 indexed imageId, address indexed enclaveKey);
    event EnclaveKeyWhitelisted(bytes32 indexed imageId, address indexed enclaveKey);
    event EnclaveKeyVerified(bytes32 indexed imageId, bytes enclaveKey);

    //-------------------------------- Declarations end --------------------------------//

    //-------------------------------- Admin methods start --------------------------------//

    error AttestationVerifierImageNotWhitelisted();
    error AttestationVerifierImageAlreadyWhitelisted();
    error AttestationVerifierKeyNotVerified();
    error AttestationVerifierKeyAlreadyVerified();
    error AttestationVerifierKeyInvalid();

    function whitelistImage(bytes memory PCR0, bytes memory PCR1, bytes memory PCR2) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _whitelistImage(EnclaveImage(PCR0, PCR1, PCR2));
    }

    function revokeWhitelistedImage(bytes32 imageId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!(whitelistedImages[imageId].PCR0.length != 0)) revert AttestationVerifierImageNotWhitelisted();
        delete whitelistedImages[imageId];
        emit WhitelistedImageRevoked(imageId);
    }

    function whitelistEnclave(bytes32 imageId, address enclaveKey) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!(whitelistedImages[imageId].PCR0.length != 0)) revert AttestationVerifierImageNotWhitelisted();
        if (!(isVerified[enclaveKey] == bytes32(0))) revert AttestationVerifierKeyAlreadyVerified();
        if (!(enclaveKey != address(0))) revert AttestationVerifierKeyInvalid();
        isVerified[enclaveKey] = imageId;
        emit EnclaveKeyWhitelisted(imageId, enclaveKey);
    }

    function revokeWhitelistedEnclave(address enclaveKey) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!(isVerified[enclaveKey] != bytes32(0))) revert AttestationVerifierKeyAlreadyVerified();
        bytes32 imageId = isVerified[enclaveKey];
        delete isVerified[enclaveKey];
        emit WhitelistedEnclaveKeyRevoked(imageId, enclaveKey);
    }

    //-------------------------------- Admin methods end --------------------------------//

    //-------------------------------- Open methods start -------------------------------//

    uint256 public constant MAX_AGE = 300;

    error AttestationVerifierAttestationTooOld();

    // This function is used to add enclave key of a whitelisted image to the list of verified enclave keys.
    function verifyEnclaveKey(
        bytes memory attestation,
        bytes memory enclavePubKey,
        bytes32 imageId,
        uint256 enclaveCPUs,
        uint256 enclaveMemory,
        // in milliseconds
        uint256 timestamp
    ) external {
        if (!(timestamp / 1000 > block.timestamp - MAX_AGE)) revert AttestationVerifierAttestationTooOld();
        if (!(whitelistedImages[imageId].PCR0.length != 0)) revert AttestationVerifierImageNotWhitelisted();

        address enclaveKey = pubKeyToAddress(enclavePubKey);
        if (!(isVerified[enclaveKey] == bytes32(0))) revert AttestationVerifierKeyAlreadyVerified();

        EnclaveImage memory image = whitelistedImages[imageId];
        _verify(attestation, enclavePubKey, image, enclaveCPUs, enclaveMemory, timestamp);

        isVerified[enclaveKey] = imageId;
        emit EnclaveKeyVerified(imageId, enclavePubKey);
    }

    //-------------------------------- Open methods end -------------------------------//

    //-------------------------------- Read only methods start -------------------------------//

    // These functions are used to verify enclave key of any image by the enclave key generated in a whitelisted image.

    function verify(
        bytes memory attestation,
        bytes memory enclaveKey,
        bytes memory PCR0,
        bytes memory PCR1,
        bytes memory PCR2,
        uint256 enclaveCPUs,
        uint256 enclaveMemory,
        uint256 timestamp
    ) external view {
        _verify(attestation, enclaveKey, EnclaveImage(PCR0, PCR1, PCR2), enclaveCPUs, enclaveMemory, timestamp);
    }

    function verify(bytes memory data) external view {
        (
            bytes memory attestation,
            bytes memory enclaveKey,
            bytes memory PCR0,
            bytes memory PCR1,
            bytes memory PCR2,
            uint256 enclaveCPUs,
            uint256 enclaveMemory,
            uint256 timestamp
        ) = abi.decode(data, (bytes, bytes, bytes, bytes, bytes, uint256, uint256, uint256));
        _verify(attestation, enclaveKey, EnclaveImage(PCR0, PCR1, PCR2), enclaveCPUs, enclaveMemory, timestamp);
    }

    //-------------------------------- Read only methods end -------------------------------//

    //-------------------------------- Internal methods start -------------------------------//

    error AttestationVerifierPCRsInvalid();
    error AttestationVerifierDoesNotVerify();

    function _whitelistImage(EnclaveImage memory image) internal returns (bytes32) {
        if (!(
            image.PCR0.length == 48 && image.PCR1.length == 48 && image.PCR2.length == 48
        )) revert AttestationVerifierPCRsInvalid();

        bytes32 imageId = keccak256(abi.encodePacked(image.PCR0, image.PCR1, image.PCR2));
        if(!(whitelistedImages[imageId].PCR0.length == 0)) revert AttestationVerifierImageAlreadyWhitelisted();
        whitelistedImages[imageId] = EnclaveImage(image.PCR0, image.PCR1, image.PCR2);
        emit EnclaveImageWhitelisted(imageId, image.PCR0, image.PCR1, image.PCR2);
        return imageId;
    }

    function _verify(
        bytes memory attestation,
        bytes memory enclaveKey,
        EnclaveImage memory image,
        uint256 enclaveCPUs,
        uint256 enclaveMemory,
        uint256 timestamp
    ) internal view {
        bytes32 digest = keccak256(
            abi.encode(
                ATTESTATION_PREFIX,
                enclaveKey,
                image.PCR0,
                image.PCR1,
                image.PCR2,
                enclaveCPUs,
                enclaveMemory,
                timestamp
            )
        );

        address signer = ECDSA.recover(digest, attestation);
        bytes32 sourceImageId = isVerified[signer];

        if (!(
            sourceImageId != bytes32(0) && whitelistedImages[sourceImageId].PCR0.length != 0
        )) revert AttestationVerifierDoesNotVerify();
    }

    //-------------------------------- Internal methods end -------------------------------//

    error AttestationVerifierPubkeyLengthInvalid();

    function pubKeyToAddress(bytes memory pubKey) public pure returns (address) {
        if (!(pubKey.length == 64)) revert AttestationVerifierPubkeyLengthInvalid();

        bytes32 hash = keccak256(pubKey);
        return address(uint160(uint256(hash)));
    }
}
