#include <libssh/libssh.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <thread>
#include <chrono>
#include <sys/stat.h>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

std::string timePointToString(const fs::file_time_type& tp) {
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(tp - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
    std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&tt), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string durationToString(const std::chrono::seconds& dur) {
    std::stringstream ss;
    ss << dur.count() << " seconds";
    return ss.str();
}

void transferFiles(const std::string& folderPath, const std::string& serverHost, const std::string& serverUser, const std::string& privateKeyPath, const std::string& serverPath, const int port) {
    ssh_session session = ssh_new();
    if (session == nullptr) {
        std::cerr << "Failed to create SSH session." << std::endl;
        return;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, serverHost.c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, serverUser.c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    //int verbosity = SSH_LOG_PROTOCOL;
    //ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    int connectStatus = ssh_connect(session);
    if (connectStatus != SSH_OK) {
        std::cerr << "Failed to connect to the server. Error code: " << connectStatus << std::endl;
        std::cerr << "Error message: " << ssh_get_error(session) << std::endl;
        ssh_free(session);
        return;
    }

    // Using the private key for authentication
    ssh_key pkey = NULL;
    int rc;

    // Import the private key from the specified file
    rc = ssh_pki_import_privkey_file(privateKeyPath.c_str(), NULL, NULL, NULL, &pkey);
    if (rc != SSH_OK) {
        std::cerr << "Error loading private key: " << ssh_get_error(session) << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    // Attempt to authenticate using the imported private key
    rc = ssh_userauth_publickey(session, serverUser.c_str(), pkey);
    if (rc != SSH_AUTH_SUCCESS) {
        std::cerr << "Authentication with private key failed: " << ssh_get_error(session) << std::endl;
        ssh_key_free(pkey);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    // Rest of the function remains the same
    ssh_scp scp = ssh_scp_new(session, SSH_SCP_WRITE, serverPath.c_str());
    if (scp == nullptr) {
        std::cerr << "Failed to create SCP session." << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    // Initialize SCP
    if (ssh_scp_init(scp) != SSH_OK) {
        std::cerr << "Failed to initialize SCP session." << std::endl;
        ssh_scp_free(scp);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    std::chrono::seconds min_delta_seconds(60);
    auto current_time = fs::file_time_type::clock::now();

    // File transfer logic
    for (const auto& entry : fs::directory_iterator(folderPath)) {
        if (entry.is_regular_file()) {
            std::string filePath = entry.path().string();
            std::string fileName = entry.path().filename().string();
            size_t fileSize = entry.file_size();

            auto last_modified_time = fs::last_write_time(filePath);
            auto difference = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_modified_time);

            if (difference > min_delta_seconds) {
                std::string current_time_str = timePointToString(current_time);
                std::string last_modified_time_str = timePointToString(last_modified_time);
                std::string difference_str = durationToString(difference);

                std::cout << "Current time: " << current_time_str << std::endl;
                std::cout << "Last modified time: " << last_modified_time_str << std::endl;
                std::cout << "Difference: " << difference_str << std::endl;

                std::ifstream fileStream(filePath, std::ios::binary);
                if (!fileStream) {
                    std::cerr << "Unable to open file: " << filePath << std::endl;
                    continue;
                }

                std::vector<char> buffer(fileSize);
                if (!fileStream.read(buffer.data(), buffer.size())) {
                    std::cerr << "Error reading file: " << filePath << std::endl;
                    continue;
                }

                fileStream.close();

                if (ssh_scp_push_file(scp, fileName.c_str(), fileSize, S_IRUSR | S_IWUSR) != SSH_OK) {
                    std::cerr << "Failed to create remote file: " << fileName << std::endl;
                    continue;
                }

                if (ssh_scp_write(scp, buffer.data(), fileSize) != SSH_OK) {
                    std::cerr << "Error writing to remote file: " << fileName << std::endl;
                    continue;
                }
                std::cout << "Successfully exported " << filePath << std::endl;
                fs::rename(filePath, folderPath + "/archive/" + fileName);
            }
        }
    }

    // Cleanup
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    ssh_disconnect(session);
    ssh_free(session);
}

void parseConfig(const std::string& filename, std::vector<std::string>& folders, std::string& serverHost, std::string& serverUser, std::string& privateKeyPath, std::string& serverPath, int& port) {
    std::ifstream file(filename);
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream is_line(line);
        std::string key;
        if (std::getline(is_line, key, '=')) {
            std::string value;
            if (std::getline(is_line, value)) {
                if (key == "folders") {
                    folders.push_back(value); // Assuming only one folder for simplicity
                }
                else if (key == "serverHost") {
                    serverHost = value;
                }
                else if (key == "serverUser") {
                    serverUser = value;
                }
                else if (key == "privateKeyPath") {
                    privateKeyPath = value;
                }
                else if (key == "serverPath") {
                    serverPath = value;
                }
                else if (key == "port") {
                    port = std::stoi(value);
                }
            }
        }
    }
}

int main() {
    std::vector<std::string> folders;
    std::string serverHost;
    std::string serverUser;
    std::string privateKeyPath;
    std::string serverPath;
    int port;

    parseConfig("config.txt", folders, serverHost, serverUser, privateKeyPath, serverPath, port);

    while (true) {
        for (const auto& folder : folders) {
            std::thread transferThread(transferFiles, folder, serverHost, serverUser, privateKeyPath, serverPath, port);
            transferThread.detach();
        }
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }

    return 0;
}