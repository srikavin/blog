import React from 'react';
import {
    Alignment,
    Button,
    Menu,
    MenuItem,
    Navbar,
    NavbarDivider,
    NavbarGroup,
    NavbarHeading,
    Popover,
    Position
} from '@blueprintjs/core';
import NavLink from './NavLink/NavLink';
import {Auth} from '../../data/resource/auth';
import Link from 'react-router-dom/es/Link';
import {IconNames} from '@blueprintjs/icons';
import {SocialIcon} from 'react-social-icons'

class Navigation extends React.Component {
    constructor(props) {
        super();
        this.state = {
            auth: Auth,
            user: {}
        };
        this.updateUser = this.updateUser.bind(this);
    }

    componentDidMount() {
        Auth.onChange(this.updateUser);
        Auth.getUser().then(e => {
            this.setState({
                user: e
            });
        });
    }

    updateUser(user) {
        console.log(user);
        this.setState({user});
    }

    render() {
        return (
            <nav>
                <Navbar>
                    <NavbarGroup align={Alignment.LEFT}>
                        <NavbarHeading>
                            <Link to={"/"}>Sharath Ramkumar</Link>
                        </NavbarHeading>
                        <NavbarDivider/>
                        <NavLink to="/" icon={IconNames.LAYOUT_AUTO} label="About"/>
                        <NavLink to="/blog" icon={IconNames.CODE} label="Blog"/>
                    </NavbarGroup>
                    <NavbarGroup align={Alignment.RIGHT}>
                        {this.state.auth.isLoggedIn() ? (
                            <div>
                                <NavLink to="/posts/new" icon="document" label="Create Post"/>
                                <Popover content={<Menu>
                                    <MenuItem text="Profile" icon="user"/>
                                    <MenuItem onClick={this.state.auth.logout} text="Logout" icon="log-out"/>
                                </Menu>} position={Position.BOTTOM}>
                                    <Button icon="user" text={this.state.user.username}/>
                                </Popover>
                            </div>
                        ) : (
                            <div>
                                <SocialIcon url="https://linkedin.com/in/htarahs" style={{ height: 25, width: 25 }}/>&nbsp;
                                <SocialIcon url="https://github.com/sharath" style={{ height: 25, width: 25 }}/>&nbsp;
                                <SocialIcon url="https://www.youtube.com/channel/UCAokuXJuHLmg1iS2yJuokjQ" style={{ height: 25, width: 25 }}/>&nbsp;
                                <SocialIcon url="https://open.spotify.com/user/qzvrwxce" style={{ height: 25, width: 25 }}/>&nbsp;
                            </div>
                            )
                        }
                    </NavbarGroup>
                </Navbar>
            </nav>
        )
    }
}

export default Navigation;