import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.android.library)
}

val nativeDir = rootProject.layout.projectDirectory.dir("native")

kotlin {
    explicitApi()

    compilerOptions {
        optIn.addAll(
            "kotlin.io.encoding.ExperimentalEncodingApi",
            "kotlinx.cinterop.ExperimentalForeignApi",
        )
    }

    androidTarget {
        publishLibraryVariants("release")
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    // Host JVM target: config parsing / generation for servers and tooling,
    // and the fast unit-test target for the shared code.
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    val xcFramework = XCFramework("VpnLib")
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        target.compilations.getByName("main").cinterops.create("vpncore") {
            definitionFile.set(project.file("src/nativeInterop/cinterop/vpncore.def"))
            includeDirs(nativeDir.dir("vpncore/include"))
        }
        target.binaries.framework {
            baseName = "VpnLib"
            // Static, so libvpncore.a (VpnCore.xcframework) is linked by the
            // app / Network Extension target in Xcode.
            isStatic = true
            xcFramework.add(this)
        }
    }

    applyDefaultHierarchyTemplate()

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.serialization.json)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

android {
    namespace = "io.github.bitnik212.vpnlib"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // libvpncore.so built by native/build-android.sh
    sourceSets["main"].jniLibs.srcDir(nativeDir.dir("build/android/jniLibs"))
}

val buildVpnCoreAndroid by tasks.registering(Exec::class) {
    group = "vpncore"
    description = "Builds libvpncore.so for all Android ABIs (needs Go and ANDROID_NDK_HOME)."
    workingDir = nativeDir.asFile
    commandLine("bash", "build-android.sh")
}

val buildVpnCoreIos by tasks.registering(Exec::class) {
    group = "vpncore"
    description = "Builds VpnCore.xcframework (needs macOS, Xcode and Go)."
    workingDir = nativeDir.asFile
    commandLine("bash", "build-ios.sh")
}
