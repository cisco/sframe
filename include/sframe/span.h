#pragma once

#include <namespace.h>

#if defined(SFRAME_USE_STD_SPAN)
#include <span>
namespace SFRAME_NAMESPACE {
using std::span;
} // namespace SFRAME_NAMESPACE
#else
#include <gsl-lite/gsl-lite.hpp>
namespace SFRAME_NAMESPACE {
using gsl_lite::span;
} // namespace SFRAME_NAMESPACE
#endif
