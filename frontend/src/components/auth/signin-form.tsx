import { cn } from "@/lib/utils";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useAuthStore } from "@/stores/useAuthStore";
import { useNavigate } from "react-router";
import { Lock, Mail, Zap } from "lucide-react";

const signInSchema = z.object({
  username: z.string().min(3, "Tên đăng nhập phải có ít nhất 3 ký tự"),
  password: z.string().min(6, "Mật khẩu phải có ít nhất 6 ký tự"),
});

type SignInFormValues = z.infer<typeof signInSchema>;

export function SigninForm({
  className,
  ...props
}: React.ComponentProps<"div">) {
  const { signIn } = useAuthStore();
  const navigate = useNavigate();
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SignInFormValues>({
    resolver: zodResolver(signInSchema),
  });

  const onSubmit = async (data: SignInFormValues) => {
    const { username, password } = data;
    await signIn(username, password);
    navigate("/");
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
                Chào mừng quay lại! Đăng nhập vào tài khoản của bạn
              </p>
            </div>

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
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
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

              {/* Password */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label
                    htmlFor="password"
                    className="block text-sm font-medium text-gray-700"
                  >
                    Mật khẩu
                  </label>
                  <a
                    href="#"
                    className="text-sm text-purple-600 hover:text-purple-700 font-medium"
                  >
                    Quên mật khẩu?
                  </a>
                </div>
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
                className="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-semibold py-3 px-4 rounded-lg transition duration-200 disabled:opacity-50"
              >
                {isSubmitting ? "Đang xử lý..." : "Đăng nhập"}
              </button>
            </form>

            {/* Footer */}
            <p className="text-center text-gray-600 text-sm mt-6">
              Chưa có tài khoản?{" "}
              <a
                href="/signup"
                className="text-purple-600 hover:text-purple-700 font-semibold"
              >
                Đăng ký
              </a>
            </p>
          </div>
        </div>

        {/* Illustration Section */}
        <div className="hidden lg:flex items-center justify-center">
          <div className="relative w-full h-full min-h-96">
            {/* Gradient Background */}
            <div className="absolute inset-0 bg-gradient-to-br from-purple-300 via-pink-300 to-blue-300 rounded-3xl opacity-20 blur-2xl"></div>

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
                  fill="#FE4A7D"
                  opacity="0.9"
                />
                <rect
                  x="35"
                  y="30"
                  width="130"
                  height="180"
                  rx="15"
                  fill="#FFE5EB"
                />

                {/* Lock Icon */}
                <circle cx="100" cy="60" r="25" fill="#8B5CF6" opacity="0.8" />
                <rect
                  x="90"
                  y="50"
                  width="20"
                  height="25"
                  rx="3"
                  fill="white"
                />
                <circle cx="100" cy="70" r="6" fill="white" />

                {/* Form Lines */}
                <rect
                  x="50"
                  y="100"
                  width="100"
                  height="8"
                  rx="4"
                  fill="#8B5CF6"
                  opacity="0.6"
                />
                <rect
                  x="50"
                  y="120"
                  width="100"
                  height="8"
                  rx="4"
                  fill="#8B5CF6"
                  opacity="0.4"
                />
                <rect
                  x="50"
                  y="140"
                  width="100"
                  height="8"
                  rx="4"
                  fill="#8B5CF6"
                  opacity="0.4"
                />

                {/* Character */}
                <circle cx="150" cy="180" r="15" fill="#7C3AED" />
                <ellipse cx="150" cy="240" rx="30" ry="35" fill="#A78BFA" />
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
