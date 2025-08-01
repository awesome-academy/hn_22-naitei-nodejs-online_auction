import { Container, Title } from "@/components/ui/index.js";

export const ChangePasswordHeader = () => {
  return (
    <div className="bg-[#241C37] pt-8 h-[40vh] relative">
      <Container>
        <div className="text-center py-16">
          <Title level={3} className="text-white mb-4">
            Change Password
          </Title>
          <div className="flex items-center justify-center gap-3">
            <Title level={5} className="text-green font-normal text-xl">Settings</Title>
            <Title level={5} className="text-white font-normal text-xl">/</Title>
            <Title level={5} className="text-white font-normal text-xl">Change Password</Title>
          </div>
        </div>
      </Container>
    </div>
  );
};
