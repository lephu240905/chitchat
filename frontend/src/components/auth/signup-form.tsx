import { cn } from "@/lib/utils";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useAuthStore } from "@/stores/useAuthStore";
import { useNavigate } from "react-router";
import { User, Mail, Lock, Zap, AlertCircle } from "lucide-react";
import { useState } from "react";

const signUpSchema = z.object({
  firstName: z.string().min(1, "Tên bắt buộc phải có"),
  lastName: z.string().min(1, "Họ bắt buộc phải có"),
  username: z.string().min(3, "Tên đăng nhập phải có ít nhất 3 ký tự"),
  email: z.email("Email không hợp lệ"),
  password: z.string().min(6, "Mật khẩu phải có ít nhất 6 ký tự"),
});

type SignUpFormValues = z.infer<typeof signUpSchema>;

export function SignupForm({
  className,
  ...props
}: React.ComponentProps<"div">) {
  const { signUp } = useAuthStore();
  const navigate = useNavigate();
  const [apiError, setApiError] = useState<string>("");

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SignUpFormValues>({
    resolver: zodResolver(signUpSchema),
  });

  const onSubmit = async (data: SignUpFormValues) => {
    setApiError("");
    const { firstName, lastName, username, email, password } = data;

    try {
      await signUp(username, password, email, firstName, lastName);
      navigate("/signin");
    } catch (error: any) {
      const errorMsg =
        error?.response?.data?.message ||
        error?.message ||
        "Đăng ký không thành công. Vui lòng thử lại.";
      setApiError(errorMsg);
    }
  };

  return (
    <div className={cn("w-full max-w-6xl", className)} {...props}>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-12">
        {/* Form Section */}
        <div className="flex flex-col justify-center">
          <div className="bg-white rounded-2xl shadow-xl p-8 md:p-10">
            {/* Header */}
            <div className="mb-8">
              <div className="flex items-center gap-2 mb-4">
                <div className="w-10 h-10 bg-gradient-to-br from-purple-600 to-pink-600 rounded-lg flex items-center justify-center">
                  <Zap className="w-6 h-6 text-white" />
                </div>
                <h1 className="text-2xl font-bold text-gray-900">Moji</h1>
              </div>
              <p className="text-gray-600 text-sm">
                Tạo tài khoản và bắt đầu hành trình của bạn
              </p>
            </div>

            {/* API Error Message */}
            {apiError && (
              <div className="mb-5 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm text-red-800 font-medium">
                    Lỗi đăng ký
                  </p>
                  <p className="text-sm text-red-600 mt-1">{apiError}</p>
                </div>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
              {/* Username */}
              <div>
                <label
                  htmlFor="username"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  Tên đăng nhập
                </label>
                <div className="relative">
                  <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="username"
                    type="text"
                    placeholder="moji"
                    className="w-full pl-11 pr-4 py-3 rounded-lg border border-gray-200 bg-gray-50 text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                    {...register("username")}
                  />
                </div>
                {errors.username && (
                  <p className="text-red-500 text-sm mt-1">
                    {errors.username.message}
                  </p>
                )}
              </div>

              {/* Họ & Tên */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label
                    htmlFor="lastName"
                    className="block text-sm font-medium text-gray-700 mb-2"
                  >
                    Họ
                  </label>
                  <div className="relative">
                    <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                    <input
                      id="lastName"
                      type="text"
                      placeholder="Nguyễn"
                      className="w-full pl-11 pr-4 py-3 rounded-lg border border-gray-200 bg-gray-50 text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                      {...register("lastName")}
                    />
                  </div>
                  {errors.lastName && (
                    <p className="text-red-500 text-sm mt-1">
                      {errors.lastName.message}
                    </p>
                  )}
                </div>
                <div>
                  <label
                    htmlFor="firstName"
                    className="block text-sm font-medium text-gray-700 mb-2"
                  >
                    Tên
                  </label>
                  <div className="relative">
                    <User className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                    <input
                      id="firstName"
                      type="text"
                      placeholder="Văn A"
                      className="w-full pl-11 pr-4 py-3 rounded-lg border border-gray-200 bg-gray-50 text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                      {...register("firstName")}
                    />
                  </div>
                  {errors.firstName && (
                    <p className="text-red-500 text-sm mt-1">
                      {errors.firstName.message}
                    </p>
                  )}
                </div>
              </div>

              {/* Email */}
              <div>
                <label
                  htmlFor="email"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  Email
                </label>
                <div className="relative">
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="email"
                    type="email"
                    placeholder="m@gmail.com"
                    className="w-full pl-11 pr-4 py-3 rounded-lg border border-gray-200 bg-gray-50 text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                    {...register("email")}
                  />
                </div>
                {errors.email && (
                  <p className="text-red-500 text-sm mt-1">
                    {errors.email.message}
                  </p>
                )}
              </div>

              {/* Password */}
              <div>
                <label
                  htmlFor="password"
                  className="block text-sm font-medium text-gray-700 mb-2"
                >
                  Mật khẩu
                </label>
                <div className="relative">
                  <Lock className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="password"
                    type="password"
                    placeholder="••••••••"
                    className="w-full pl-11 pr-4 py-3 rounded-lg border border-gray-200 bg-gray-50 text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:border-transparent transition"
                    {...register("password")}
                  />
                </div>
                {errors.password && (
                  <p className="text-red-500 text-sm mt-1">
                    {errors.password.message}
                  </p>
                )}
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-semibold py-3 px-4 rounded-lg transition duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting ? "Đang xử lý..." : "Tạo tài khoản"}
              </button>
            </form>

            {/* Footer */}
            <p className="text-center text-gray-600 text-sm mt-6">
              Đã có tài khoản?{" "}
              <a
                href="/signin"
                className="text-purple-600 hover:text-purple-700 font-semibold"
              >
                Đăng nhập
              </a>
            </p>
          </div>
        </div>

        {/* Illustration Section */}
        <div className="hidden lg:flex items-center justify-center">
          <div className="relative w-full h-full min-h-96">
            {/* Gradient Background */}
            <div className="absolute inset-0 bg-gradient-to-br from-pink-300 via-purple-300 to-yellow-200 rounded-3xl opacity-20 blur-2xl"></div>

            {/* Main Illustration */}
            <div className="relative flex items-center justify-center h-full">
              <svg
                viewBox="0 0 200 300"
                className="w-full h-full max-w-xs drop-shadow-2xl"
              >
                {/* Device */}
                <rect
                  x="30"
                  y="20"
                  width="140"
                  height="200"
                  rx="20"
                  fill="#FBBF24"
                  opacity="0.9"
                />
                <rect
                  x="35"
                  y="30"
                  width="130"
                  height="180"
                  rx="15"
                  fill="#FEF3C7"
                />

                {/* Top Section */}
                <rect
                  x="50"
                  y="45"
                  width="100"
                  height="35"
                  rx="4"
                  fill="#8B5CF6"
                  opacity="0.7"
                />
                <circle cx="100" cy="62" r="8" fill="white" />

                {/* Form Lines */}
                <rect
                  x="50"
                  y="95"
                  width="100"
                  height="6"
                  rx="3"
                  fill="#8B5CF6"
                  opacity="0.5"
                />
                <rect
                  x="50"
                  y="110"
                  width="100"
                  height="6"
                  rx="3"
                  fill="#8B5CF6"
                  opacity="0.3"
                />
                <rect
                  x="50"
                  y="125"
                  width="60"
                  height="6"
                  rx="3"
                  fill="#8B5CF6"
                  opacity="0.3"
                />

                {/* Character */}
                <circle cx="140" cy="250" r="12" fill="#7C3AED" />
                <ellipse
                  cx="140"
                  cy="280"
                  rx="25"
                  ry="15"
                  fill="#A78BFA"
                  opacity="0.8"
                />
              </svg>
            </div>
          </div>
        </div>
      </div>

      {/* Terms */}
      <div className="text-xs text-balance px-6 text-center text-gray-500 mt-6">
        Bằng cách tiếp tục, bạn đồng ý với{" "}
        <a href="#" className="underline hover:text-purple-600">
          Điều khoản dịch vụ
        </a>{" "}
        và{" "}
        <a href="#" className="underline hover:text-purple-600">
          Chính sách bảo mật
        </a>{" "}
        của chúng tôi.
      </div>
    </div>
  );
}
