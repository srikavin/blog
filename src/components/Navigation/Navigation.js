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
import {FaGithub, FaLinkedinSquare, FaSpotify, FaSteam, FaYoutube} from 'react-icons/lib/fa/';
import './Navigation.css'

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

    redirect(url) {
        return () => {
            window.open(url, '_blank')
        }
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
                                <FaLinkedinSquare className={'navExternIconLink'} onClick={this.redirect("https://linkedin.com/in/htarahs")} size={25}/>&nbsp;
                                <FaGithub className={'navExternIconLink'} onClick={this.redirect("https://github.com/sharath")} size={25}/>&nbsp;
                                <FaYoutube className={'navExternIconLink'} onClick={this.redirect("https://www.youtube.com/channel/UCAokuXJuHLmg1iS2yJuokjQ")} size={25}/>&nbsp;
                                <FaSpotify className={'navExternIconLink'} onClick={this.redirect("https://open.spotify.com/user/qzvrwxce")} size={25}/>&nbsp;
                                <FaSteam className={'navExternIconLink'} onClick={this.redirect("https://steamcommunity.com/id/hdplus/")} size={25}/>&nbsp;
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